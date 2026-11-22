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
