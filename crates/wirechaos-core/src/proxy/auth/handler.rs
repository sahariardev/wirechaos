use crate::proxy::ProxyError;
use crate::proxy::auth::error::{AuthError, AuthFailure};
use crate::proxy::auth::verifier::VerifierProvider;
use crate::proxy::conn::Conn;
use tracing::warn;

const MSG_AUTH: u8 = b'R';
const MSG_ERROR: u8 = b'E';

impl<V: VerifierProvider> Conn<V> {
    pub async fn handle_authentication(
        &mut self,
    ) -> Result<Option<Vec<u8>>, ProxyError> {
        match self.handle_scram_auth().await {
            Ok(client_key) => Ok(client_key),
            Err(AuthFailure::Rejected(error)) => {
                // The record that survives the rejection: the client is told its
                // SQLSTATE, but nothing upstream sees an error. Message and user
                // are both client-influenced by now, so they are formatted with
                // `?` — Debug escapes newlines and control bytes that would
                // otherwise let a client forge log lines.
                warn!(
                    code = error.code(),
                    message = ?error.message(),
                    user = ?self.user.as_deref(),
                    "authentication rejected"
                );

                self.send_protocol_error(error.as_ref()).await?;
                Ok(None)
            }
            Err(AuthFailure::Internal(error)) => Err(error),
        }
    }

    pub async fn send_auth_message(
        &mut self,
        sub_code: i32,
        data: &[u8],
    ) -> Result<(), ProxyError> {
        let mut body = Vec::with_capacity(data.len() + 4);
        body.extend_from_slice(&sub_code.to_be_bytes());
        body.extend_from_slice(data);
        self.write_message(MSG_AUTH, &body).await?;
        Ok(())
    }

    async fn send_protocol_error(
        &mut self,
        err: &dyn AuthError,
    ) -> Result<(), ProxyError> {
        self.write_message(MSG_ERROR, &prepare_error_buf("FATAL", err.code(), err.message()))
            .await?;
        Ok(())
    }
}

fn prepare_error_buf(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();

    body.push(b'S');
    put_cstr(&mut body, severity);
    body.push(b'V');
    put_cstr(&mut body, severity);
    body.push(b'C');
    put_cstr(&mut body, code);
    body.push(b'M');
    put_cstr(&mut body, message);
    body.push(b'\0');
    body
}
//append value as c str (bytes + tailing nul)
fn put_cstr(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\0');
}
