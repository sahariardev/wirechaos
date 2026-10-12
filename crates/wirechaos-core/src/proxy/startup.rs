pub enum SessionState {
    Connected,
    TlsNegotiated,
    StartupReceived,
    Authenticated,
    Ready,
    Closing,
}

pub enum Incomig {
    SslRequest,
    GssEncRequest,
    StartupMessage,
    CancelRequest,
    SaslResponse,
    Query,
    Terminate,
}

impl SessionState {
    pub fn accepts(self, incoming: Incoming) -> bool {
        match (self, incoming) {
            (Connected, SslRequest | GssEncRequest | StartupMessage | CancelRequest) => true,
            (TlsNegotiated, GssEncRequest | StartupMessage) => true,
            (StartupReceived, SaslResponse) => true,
            (Ready, Query | Terminate) => true,
            _ => false,
        }
    }
}
