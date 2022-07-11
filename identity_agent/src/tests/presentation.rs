// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A conceptual implementation of the IOTA DIDComm presentation protocol.
//! It merely sends the appropriate messages back and forth, but without any actual content.
//! It exists to prove the concept for the DIDComm agent.
//!
//! See for details: https://wiki.iota.org/identity.rs/specs/didcomm/protocols/presentation.

use serde::Deserialize;
use serde::Serialize;

use crate::agent::AgentId;
use crate::agent::Endpoint;
use crate::agent::RequestContext;
use crate::agent::Result as AgentResult;
use crate::didcomm::DidCommAgent;
use crate::didcomm::DidCommHandler;
use crate::didcomm::DidCommPlaintextMessage;
use crate::didcomm::DidCommRequest;
use crate::didcomm::ThreadId;

#[derive(Debug, Clone)]
pub(crate) struct DidCommState;

impl DidCommState {
  pub(crate) fn new() -> Self {
    Self
  }
}

#[async_trait::async_trait]
impl DidCommHandler<DidCommPlaintextMessage<PresentationRequest>> for DidCommState {
  async fn handle(&self, agent: DidCommAgent, request: RequestContext<DidCommPlaintextMessage<PresentationRequest>>) {
    log::debug!("holder: received presentation request");

    let result = presentation_holder_handler(agent, request.agent_id, Some(request.input)).await;

    if let Err(err) = result {
      log::error!("presentation holder handler errored: {err:?}");
    }
  }
}

#[async_trait::async_trait]
impl DidCommHandler<DidCommPlaintextMessage<PresentationOffer>> for DidCommState {
  async fn handle(&self, agent: DidCommAgent, request: RequestContext<DidCommPlaintextMessage<PresentationOffer>>) {
    log::debug!("verifier: received offer from {}", request.agent_id);

    let result = presentation_verifier_handler(agent, request.agent_id, Some(request.input)).await;

    if let Err(err) = result {
      log::error!("presentation verifier handler errored: {err:?}");
    }
  }
}

/// The presentation protocol for the handler.
///
/// If `request` is `None`, the holder initiates the protocol, otherwise the verifier initiated
/// by sending a `PresentationRequest`.
pub(crate) async fn presentation_holder_handler(
  mut agent: DidCommAgent,
  agent_id: AgentId,
  request: Option<DidCommPlaintextMessage<PresentationRequest>>,
) -> AgentResult<()> {
  let request: DidCommPlaintextMessage<PresentationRequest> = match request {
    Some(request) => request,
    None => {
      log::debug!("holder: sending presentation offer");
      let thread_id = ThreadId::new();
      agent
        .send_didcomm_request(agent_id, &thread_id, PresentationOffer::default())
        .await?;

      let req = agent.await_didcomm_request(&thread_id).await;
      log::debug!("holder: received presentation request");

      req?
    }
  };

  let thread_id = request.thread_id();

  log::debug!("holder: sending presentation");
  agent
    .send_didcomm_request(agent_id, thread_id, Presentation::default())
    .await?;

  let _result: DidCommPlaintextMessage<PresentationResult> = agent.await_didcomm_request(thread_id).await?;
  log::debug!("holder: received presentation result");

  Ok(())
}

/// The presentation protocol for the verifier.
///
/// If `offer` is `None`, the verifier initiates the protocol, otherwise the holder initiated
/// by sending a `PresentationOffer`.
pub(crate) async fn presentation_verifier_handler(
  mut agent: DidCommAgent,
  agent_id: AgentId,
  offer: Option<DidCommPlaintextMessage<PresentationOffer>>,
) -> AgentResult<()> {
  let thread_id: ThreadId = if let Some(offer) = offer {
    offer.thread_id().to_owned()
  } else {
    ThreadId::new()
  };

  log::debug!("verifier: sending request");
  agent
    .send_didcomm_request(agent_id, &thread_id, PresentationRequest::default())
    .await?;

  log::debug!("verifier: awaiting presentation");
  let presentation: DidCommPlaintextMessage<Presentation> = agent.await_didcomm_request(&thread_id).await?;
  log::debug!("verifier: received presentation: {:?}", presentation);

  log::debug!("verifier: sending presentation result");
  agent
    .send_didcomm_request(agent_id, &thread_id, PresentationResult::default())
    .await?;
  Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(crate) struct PresentationRequest([u8; 2]);

impl DidCommRequest for PresentationRequest {
  fn endpoint() -> Endpoint {
    "didcomm/presentation_request".try_into().unwrap()
  }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(crate) struct PresentationOffer([u8; 3]);

impl DidCommRequest for PresentationOffer {
  fn endpoint() -> Endpoint {
    "didcomm/presentation_offer".try_into().unwrap()
  }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(crate) struct Presentation([u8; 4]);

impl DidCommRequest for Presentation {
  fn endpoint() -> Endpoint {
    "didcomm/presentation".try_into().unwrap()
  }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(crate) struct PresentationResult([u8; 5]);

impl DidCommRequest for PresentationResult {
  fn endpoint() -> Endpoint {
    "didcomm/presentation_result".try_into().unwrap()
  }
}
