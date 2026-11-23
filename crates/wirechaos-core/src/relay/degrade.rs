#![allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyAccess {
    Complete,
    Streamed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionRequirement {
    FrameOnly,
    WholeBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionKind {
    Delay,
    DropFast,
    Terminate,
    Notice,
    Replace,
    Duplicate,
    Truncate,
    InspectValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Degradation {
    Allowed(ActionKind),
    Refused { reason: &'static str },
}

#[allow(dead_code)]
pub(crate) fn degrade(
    requirement: ActionRequirement,
    access: BodyAccess,
    requested: ActionKind,
) -> Degradation {
    if requirement == ActionRequirement::FrameOnly {
        return match requested {
            ActionKind::Delay
            | ActionKind::DropFast
            | ActionKind::Terminate
            | ActionKind::Notice => Degradation::Allowed(requested),
            _ => Degradation::Refused {
                reason: "action requires a whole body but was classified frame-only",
            },
        };
    }

    match access {
        BodyAccess::Complete => Degradation::Allowed(requested),
        BodyAccess::Streamed => match requested {
            ActionKind::Delay => Degradation::Allowed(ActionKind::Delay),
            ActionKind::DropFast => Degradation::Allowed(ActionKind::DropFast),
            ActionKind::Terminate => Degradation::Allowed(ActionKind::Terminate),
            ActionKind::Notice => Degradation::Allowed(ActionKind::Notice),

            ActionKind::Replace
            | ActionKind::Duplicate
            | ActionKind::Truncate
            | ActionKind::InspectValue => Degradation::Refused {
                reason: "full-body action cannot run on a streamed body",
            },
        },
        BodyAccess::Unavailable => Degradation::Refused {
            reason: "body is unavailable and the action requires it",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_body_action_on_streamed_frame_degrades() {
        let decision = degrade(
            ActionRequirement::WholeBody,
            BodyAccess::Streamed,
            ActionKind::Replace,
        );
        assert!(matches!(decision, Degradation::Refused { .. }));
    }

    #[test]
    fn replace_and_duplicate_are_refused_on_streams() {
        for action in [
            ActionKind::Replace,
            ActionKind::Duplicate,
            ActionKind::Truncate,
            ActionKind::InspectValue,
        ] {
            assert!(matches!(
                degrade(ActionRequirement::WholeBody, BodyAccess::Streamed, action),
                Degradation::Refused { .. }
            ));
        }
    }

    #[test]
    fn delay_drop_and_terminate_are_allowed_on_streams() {
        for action in [
            ActionKind::Delay,
            ActionKind::DropFast,
            ActionKind::Terminate,
        ] {
            assert_eq!(
                degrade(ActionRequirement::FrameOnly, BodyAccess::Streamed, action),
                Degradation::Allowed(action)
            );
        }
    }

    #[test]
    fn complete_body_actions_are_unchanged() {
        assert_eq!(
            degrade(
                ActionRequirement::WholeBody,
                BodyAccess::Complete,
                ActionKind::Replace
            ),
            Degradation::Allowed(ActionKind::Replace)
        );
    }

    #[test]
    fn unavailable_body_refuses_whole_body_actions() {
        let decision = degrade(
            ActionRequirement::WholeBody,
            BodyAccess::Unavailable,
            ActionKind::Duplicate,
        );
        assert!(matches!(decision, Degradation::Refused { .. }));
    }
}
