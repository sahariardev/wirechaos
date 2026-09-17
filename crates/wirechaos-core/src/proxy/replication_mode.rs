/// How the client asked to be treated by the `replication` startup parameter.
///
/// Mirrors PostgreSQL's values for that parameter: absent/`false`/`off` is a normal
/// session, `true`/`on`/`1` is physical replication, and `database` is logical
/// replication. See doc/tasks/04-startup-phase-completion.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplicationMode {
    #[default]
    Off,
    Physical,
    Logical,
}
