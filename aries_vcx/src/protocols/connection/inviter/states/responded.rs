use std::clone::Clone;

use crate::did_doc::DidDoc;
use crate::messages::ack::Ack;
use crate::messages::connection::problem_report::ProblemReport;
use crate::messages::connection::response::SignedResponse;
use crate::messages::trust_ping::ping::Ping;
use crate::messages::trust_ping::ping_response::PingResponse;
use crate::protocols::connection::inviter::states::complete::CompleteState;
use crate::protocols::connection::inviter::states::initial::InitialState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RespondedState {
    pub signed_response: SignedResponse,
    pub did_doc: DidDoc,
}

impl From<(RespondedState, ProblemReport)> for InitialState {
    fn from((_state, problem_report): (RespondedState, ProblemReport)) -> InitialState {
        trace!("ConnectionInviter: transit state from RespondedState to InitialState, problem_report: {:?}", problem_report);
        InitialState::new(Some(problem_report))
    }
}

impl From<(RespondedState, Ack)> for CompleteState {
    fn from((state, _ack): (RespondedState, Ack)) -> CompleteState {
        trace!("ConnectionInviter: transit state from RespondedState to CompleteState");
        CompleteState { did_doc: state.did_doc, thread_id: Some(state.signed_response.get_thread_id()), protocols: None }
    }
}

impl From<(RespondedState, Ping)> for CompleteState {
    fn from((state, _ping): (RespondedState, Ping)) -> CompleteState {
        trace!("ConnectionInviter: transit state from RespondedState to CompleteState");
        CompleteState { did_doc: state.did_doc, thread_id: Some(state.signed_response.get_thread_id()), protocols: None }
    }
}

impl From<(RespondedState, PingResponse)> for CompleteState {
    fn from((state, _ping_response): (RespondedState, PingResponse)) -> CompleteState {
        trace!("ConnectionInviter: transit state from RespondedState to CompleteState");
        CompleteState { did_doc: state.did_doc, thread_id: Some(state.signed_response.get_thread_id()), protocols: None }
    }
}
