#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub(crate) enum Direction {
    FrontendToBackend,
    BackendToFrontend,
}
