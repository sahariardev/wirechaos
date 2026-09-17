use crate::auth::error::ScramError;
use crate::auth::scram::ScramAuthenticator;
use crate::auth::verifier::VerifierProvider;
use crate::proxy::conn::Conn;
use crate::proxy::packet::MessageReader;
use tokio::io;
use tokio::io::AsyncReadExt;

const MSG_AUTH: u8 = b'R';
const MSG_PASSWORD: u8 = b'p';
const MSG_ERROR: u8 = b'E';
const AUTH_SASL: i32 = 10;
const AUTH_SASL_CONTINUE: i32 = 11;
const AUTH_SASL_FINAL: i32 = 12;
impl<V: VerifierProvider> Conn<V> {
    pub async fn handle_authentication(
        &mut self,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        // A startup message without a `user` cannot be authenticated, and a
        // missing parameter must not panic the connection.
        let user = self
            .user
            .clone()
            .filter(|user| !user.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup message did not provide a user",
                )
            })?;

        let verifier = self.provider.get(&user)?;
        let mut scram = ScramAuthenticator::new(&verifier);
        let mechanics = scram.mechanisms();

        self.send_auth_sasl(&mechanics).await?;
        let (chosen, client_first) = self.read_sasl_initial_response(&mechanics).await?;

        let server_first = match scram.handle_client_first(&chosen, &client_first, &user) {
            Ok(message) => message,

            Err(e) => {
                self.send_protocol_error(&e).await?;
                return Ok(None);
            }
        };

        self.send_auth_message(AUTH_SASL_CONTINUE, server_first.as_bytes())
            .await?;

        let client_final = self.read_sasl_final_response().await?;

        let server_final = match scram.handle_client_final(&client_final) {
            Ok(server_final) => server_final,
            Err(ScramError::AuthenticationFailed) => {
                self.send_auth_failed(&user).await?;
                return Ok(None);
            }
            Err(e) => {
                self.send_protocol_error(&e).await?;
                return Ok(None);
            }
        };

        self.send_auth_message(AUTH_SASL_FINAL, server_final.as_bytes())
            .await?;

        Ok(scram.extracted_client_key().map(|k| k.to_vec()))
    }

    async fn read_sasl_initial_response(
        &mut self,
        mechanics: &Vec<&str>,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        //read first byte
        let mut buf = [0u8; 1];
        self.buffer_reader.read_exact(&mut buf).await?;

        if buf[0] != MSG_PASSWORD {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message",
            )));
        }

        let len = self.read_message_length().await?;

        if len < 4 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Message length too short",
            )));
        }

        let Some(message_buf) = self.read_message_body(len).await? else {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Message body is empty",
            )));
        };

        let mut message = MessageReader::new(message_buf);

        let mechanism = message.read_string()?;

        if !mechanics.contains(&mechanism.as_str()) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mechanism",
            )));
        }

        let data_len = message.read_u32()? as i32;

        if data_len < 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message length too short",
            )));
        }

        let client_first = message.read_string_fixed_size(data_len)?;

        Ok((mechanism, client_first))
    }

    async fn read_sasl_final_response(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let mut buf = [0u8; 1];
        self.buffer_reader.read_exact(&mut buf).await?;

        if buf[0] != MSG_PASSWORD {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message",
            )));
        }

        let len = self.read_message_length().await?;

        if len < 4 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Message length too short",
            )));
        }

        let Some(message_buf) = self.read_message_body(len).await? else {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Message body is empty",
            )));
        };

        Ok(String::from_utf8_lossy(&message_buf).into_owned())
    }
    async fn send_auth_sasl(
        &mut self,
        mechanics: &Vec<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut data = Vec::new();

        for m in mechanics {
            put_cstr(&mut data, m);
        }

        data.push(b'\0');
        self.send_auth_message(AUTH_SASL, &data).await?;

        Ok(())
    }

    async fn send_auth_message(
        &mut self,
        sub_code: i32,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut body = Vec::with_capacity(data.len() + 4);
        body.extend_from_slice(&sub_code.to_be_bytes());
        body.extend_from_slice(data);
        self.write_message(MSG_AUTH, &body).await?;
        Ok(())
    }

    async fn send_protocol_error(
        &mut self,
        err: &ScramError,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let msg = match err {
            ScramError::AuthenticationFailed => "Authentication failed".to_string(),
            ScramError::Protocol(msg) => format!("malformed SCRAM message: {}", msg),
        };

        self.write_message(MSG_ERROR, &prepare_error_buf("FATAL", "", &msg))
            .await?;

        Ok(())
    }

    async fn send_auth_failed(&mut self, user: &str) -> Result<(), Box<dyn std::error::Error>> {
        let msg = format!("password authentication failed for user \"{user}\"");

        self.write_message(MSG_ERROR, &prepare_error_buf("FATAL", "28P01", &msg))
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
