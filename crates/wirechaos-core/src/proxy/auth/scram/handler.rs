use crate::proxy::auth::error::AuthFailure;
use crate::proxy::auth::scram::error::ScramError;
use crate::proxy::auth::scram::scram_authenticator::ScramAuthenticator;
use crate::proxy::auth::verifier::VerifierProvider;
use crate::proxy::conn::Conn;
use crate::proxy::packet::MessageReader;
use tokio::io::AsyncReadExt;
use tracing::warn;
use crate::proxy::buffer_pool::PooledBytes;

const MSG_PASSWORD: u8 = b'p';
const AUTH_SASL: i32 = 10;
const AUTH_SASL_CONTINUE: i32 = 11;
const AUTH_SASL_FINAL: i32 = 12;
const AUTH_SASL_OK: i32 = 0;

impl<V: VerifierProvider> Conn<V> {
    pub async fn handle_scram_auth(&mut self) -> Result<Option<Vec<u8>>, AuthFailure> {
        let user = self
            .user
            .clone()
            .filter(|user| !user.is_empty())
            .ok_or_else(|| {
                AuthFailure::rejected(ScramError::AuthenticationFailed(
                    "password authentication failed for user".to_string(),
                ))
            })?;

        let verifier = match self.provider.lookup(&user) {
            Ok(Some(verifier)) => verifier,
            Ok(None) => {
                // The client is answered exactly as for a wrong password, but
                // the two must stay distinguishable on the server side. `?user`
                // escapes it: the name came off the wire.
                warn!(user = ?user, "authentication rejected: unknown user");
                return Err(AuthFailure::rejected(ScramError::AuthenticationFailed(
                    format!("password authentication failed for user {}", user),
                )));
            }
            Err(e) => {
                // A credential-store fault, not a client mistake — it gets its
                // own line so a store outage is not lost among failed logins.
                warn!(user = ?user, error = %e, "credential lookup failed");
                return Err(AuthFailure::rejected(e));
            }
        };

        let mut scram = ScramAuthenticator::new(&verifier);
        let mechanics = scram.mechanisms();

        self.send_auth_sasl(&mechanics)
            .await
            .map_err(AuthFailure::internal)?;
        let (chosen, client_first) = self.read_sasl_initial_response(&mechanics).await?;

        let server_first = scram
            .handle_client_first(&chosen, &client_first, &user)
            .map_err(AuthFailure::rejected)?;

        self.send_auth_message(AUTH_SASL_CONTINUE, server_first.as_bytes())
            .await
            .map_err(AuthFailure::internal)?;

        let client_final = self.read_sasl_final_response().await?;

        let server_final = scram
            .handle_client_final(&client_final, &user)
            .map_err(AuthFailure::rejected)?;

        self.send_auth_message(AUTH_SASL_FINAL, server_final.as_bytes())
            .await
            .map_err(AuthFailure::internal)?;

        self.send_auth_message(AUTH_SASL_OK, &[])
            .await
            .map_err(AuthFailure::internal)?;

        Ok(scram.extracted_client_key().map(|k| k.to_vec()))
    }

    async fn read_sasl_response(&mut self) -> Result<PooledBytes,AuthFailure> {
        //read first byte
        let mut buf = [0u8; 1];
        self.buffer_reader
            .read_exact(&mut buf)
            .await
            .map_err(AuthFailure::internal)?;

        if buf[0] != MSG_PASSWORD {
            return Err(AuthFailure::rejected(ScramError::Protocol(
                "Invalid Message".to_owned(),
            )));
        }

        let len = self
            .read_message_length()
            .await
            .map_err(AuthFailure::internal)?;

        if len < 4 {
            return Err(AuthFailure::rejected(ScramError::Protocol(
                "message length too short".to_owned(),
            )));
        }

        let Some(message_buf) = self
            .read_message_body(len)
            .await
            .map_err(AuthFailure::internal)?
        else {
            return Err(AuthFailure::rejected(ScramError::Protocol(
                "message body empty".to_owned(),
            )));
        };

        Ok(message_buf)
    }
    async fn read_sasl_initial_response(
        &mut self,
        mechanics: &[&str],
    ) -> Result<(String, String), AuthFailure> {
        let message_buf = self.read_sasl_response().await?;

        let mut message = MessageReader::new(message_buf);

        let mechanism = message.read_string().map_err(AuthFailure::internal)?;

        if !mechanics.contains(&mechanism.as_str()) {
            return Err(AuthFailure::rejected(ScramError::Protocol(
                "invalid mechanism".to_owned(),
            )));
        }

        let data_len = message.read_u32().map_err(AuthFailure::internal)? as i32;

        if data_len < 0 {
            return Err(AuthFailure::rejected(ScramError::Protocol(
                "Invalid message".to_owned(),
            )));
        }

        let client_first = message
            .read_string_fixed_size(data_len)
            .map_err(|_| AuthFailure::rejected(ScramError::Protocol(
                "Invalid message".to_owned(),
            )))?;

        Ok((mechanism, client_first))
    }

    async fn read_sasl_final_response(&mut self) -> Result<String, AuthFailure> {
        let message_buf = self.read_sasl_response().await?;

        String::from_utf8(message_buf.to_vec()).map_err(|_| {
            AuthFailure::rejected(ScramError::Protocol(
                "malformed SCRAM message".to_owned(),
            ))
        })
    }

    async fn send_auth_sasl(&mut self, mechanics: &[&str]) -> Result<(), AuthFailure> {
        let mut data = Vec::new();

        for m in mechanics {
            put_cstr(&mut data, m);
        }

        data.push(b'\0');
        self.send_auth_message(AUTH_SASL, &data)
            .await
            .map_err(AuthFailure::internal)?;

        Ok(())
    }
}

//append value as c str (bytes + tailing nul)
fn put_cstr(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\0');
}
