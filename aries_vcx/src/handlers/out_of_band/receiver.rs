use std::{clone::Clone, fmt::Display, str::FromStr};

use agency_client::agency_client::AgencyClient;
use aries_vcx_core::{ledger::base_ledger::IndyLedgerRead, wallet::base_wallet::BaseWallet};
use base64::{engine::general_purpose, Engine};
use diddoc_legacy::aries::diddoc::AriesDidDoc;
use messages::{
    decorators::attachment::{Attachment, AttachmentType},
    msg_fields::protocols::{
        cred_issuance::v1::offer_credential::OfferCredentialV1,
        out_of_band::{
            invitation::{Invitation, OobService},
            OutOfBand,
        },
        present_proof::v1::request::RequestPresentationV1,
    },
    AriesMessage,
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    common::ledger::transactions::resolve_service,
    errors::error::prelude::*,
    handlers::{
        mediated_connection::MediatedConnection,
        util::{AnyInvitation, AttachmentId},
    },
    protocols::connection::GenericConnection,
};

#[derive(Debug, PartialEq, Clone)]
pub struct OutOfBandReceiver {
    pub oob: Invitation,
}

impl OutOfBandReceiver {
    pub fn create_from_a2a_msg(msg: &AriesMessage) -> VcxResult<Self> {
        trace!("OutOfBandReceiver::create_from_a2a_msg >>> msg: {:?}", msg);
        match msg {
            AriesMessage::OutOfBand(OutOfBand::Invitation(oob)) => {
                Ok(OutOfBandReceiver { oob: oob.clone() })
            }
            m => Err(AriesVcxError::from_msg(
                AriesVcxErrorKind::InvalidMessageFormat,
                format!(
                    "Expected OutOfBandInvitation message to create OutOfBandReceiver, but \
                     received message of unknown type: {:?}",
                    m
                ),
            )),
        }
    }

    pub fn get_id(&self) -> String {
        self.oob.id.clone()
    }

    pub async fn connection_exists<'a>(
        &self,
        indy_ledger: &impl IndyLedgerRead,
        connections: &'a Vec<&'a MediatedConnection>,
    ) -> VcxResult<Option<&'a MediatedConnection>> {
        trace!("OutOfBandReceiver::connection_exists >>>");
        for service in &self.oob.content.services {
            for connection in connections {
                match connection.bootstrap_did_doc() {
                    Some(did_doc) => {
                        if let OobService::Did(did) = service {
                            if did == &did_doc.id {
                                return Ok(Some(connection));
                            }
                        };
                        if did_doc.get_service()? == resolve_service(indy_ledger, service).await? {
                            return Ok(Some(connection));
                        };
                    }
                    None => break,
                }
            }
        }
        Ok(None)
    }

    pub async fn nonmediated_connection_exists<'a, I, T>(
        &self,
        indy_ledger: &impl IndyLedgerRead,
        connections: I,
    ) -> Option<T>
    where
        I: IntoIterator<Item = (T, &'a GenericConnection)> + Clone,
    {
        trace!("OutOfBandReceiver::connection_exists >>>");

        for service in &self.oob.content.services {
            for (idx, connection) in connections.clone() {
                if Self::connection_matches_service(indy_ledger, connection, service).await {
                    return Some(idx);
                }
            }
        }

        None
    }

    async fn connection_matches_service(
        indy_ledger: &impl IndyLedgerRead,
        connection: &GenericConnection,
        service: &OobService,
    ) -> bool {
        match connection.bootstrap_did_doc() {
            None => false,
            Some(did_doc) => Self::did_doc_matches_service(indy_ledger, service, did_doc).await,
        }
    }

    async fn did_doc_matches_service(
        indy_ledger: &impl IndyLedgerRead,
        service: &OobService,
        did_doc: &AriesDidDoc,
    ) -> bool {
        // Ugly, but it's best to short-circuit.
        Self::did_doc_matches_service_did(service, did_doc)
            || Self::did_doc_matches_resolved_service(indy_ledger, service, did_doc)
                .await
                .unwrap_or(false)
    }

    fn did_doc_matches_service_did(service: &OobService, did_doc: &AriesDidDoc) -> bool {
        match service {
            OobService::Did(did) => did == &did_doc.id,
            _ => false,
        }
    }

    async fn did_doc_matches_resolved_service(
        indy_ledger: &impl IndyLedgerRead,
        service: &OobService,
        did_doc: &AriesDidDoc,
    ) -> VcxResult<bool> {
        let did_doc_service = did_doc.get_service()?;
        let oob_service = resolve_service(indy_ledger, service).await?;

        Ok(did_doc_service == oob_service)
    }

    // TODO: There may be multiple A2AMessages in a single OoB msg
    pub fn extract_a2a_message(&self) -> VcxResult<Option<AriesMessage>> {
        trace!("OutOfBandReceiver::extract_a2a_message >>>");
        if let Some(attach) = self
            .oob
            .content
            .requests_attach
            .as_ref()
            .and_then(|v| v.get(0))
        {
            attachment_to_aries_message(attach)
        } else {
            Ok(None)
        }
    }

    pub async fn build_connection(
        &self,
        wallet: &impl BaseWallet,
        agency_client: &AgencyClient,
        did_doc: AriesDidDoc,
        autohop_enabled: bool,
    ) -> VcxResult<MediatedConnection> {
        trace!(
            "OutOfBandReceiver::build_connection >>> autohop_enabled: {}",
            autohop_enabled
        );
        MediatedConnection::create_with_invite(
            &self.oob.id,
            wallet,
            agency_client,
            AnyInvitation::Oob(self.oob.clone()),
            did_doc,
            autohop_enabled,
        )
        .await
    }

    pub fn to_aries_message(&self) -> AriesMessage {
        self.oob.clone().into()
    }

    pub fn from_string(oob_data: &str) -> VcxResult<Self> {
        Ok(Self {
            oob: serde_json::from_str(oob_data)?,
        })
    }
}

impl Display for OutOfBandReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", json!(AriesMessage::from(self.oob.clone())))
    }
}

fn attachment_to_aries_message(attach: &Attachment) -> VcxResult<Option<AriesMessage>> {
    let AttachmentType::Base64(encoded_attach) = &attach.data.content else {
        return Err(AriesVcxError::from_msg(
            AriesVcxErrorKind::SerializationError,
            format!("Attachment is not base 64 encoded JSON: {attach:?}"),
        ));
    };

    let Ok(bytes) = general_purpose::STANDARD.decode(encoded_attach) else {
        return Err(AriesVcxError::from_msg(
            AriesVcxErrorKind::SerializationError,
            format!("Attachment is not base 64 encoded JSON: {attach:?}"),
        ));
    };

    let attach_json: Value = serde_json::from_slice(&bytes).map_err(|_| {
        AriesVcxError::from_msg(
            AriesVcxErrorKind::SerializationError,
            format!("Attachment is not base 64 encoded JSON: {attach:?}"),
        )
    })?;

    let attach_id = if let Some(attach_id) = attach.id.as_deref() {
        AttachmentId::from_str(attach_id).map_err(|err| {
            AriesVcxError::from_msg(
                AriesVcxErrorKind::SerializationError,
                format!("Failed to deserialize attachment ID: {}", err),
            )
        })
    } else {
        Err(AriesVcxError::from_msg(
            AriesVcxErrorKind::InvalidMessageFormat,
            format!("Missing attachment ID on attach: {attach:?}"),
        ))
    }?;

    match attach_id {
        AttachmentId::CredentialOffer => {
            let offer = OfferCredentialV1::deserialize(&attach_json).map_err(|_| {
                AriesVcxError::from_msg(
                    AriesVcxErrorKind::SerializationError,
                    format!("Failed to deserialize attachment: {attach_json:?}"),
                )
            })?;
            Ok(Some(offer.into()))
        }
        AttachmentId::PresentationRequest => {
            let request = RequestPresentationV1::deserialize(&attach_json).map_err(|_| {
                AriesVcxError::from_msg(
                    AriesVcxErrorKind::SerializationError,
                    format!("Failed to deserialize attachment: {attach_json:?}"),
                )
            })?;
            Ok(Some(request.into()))
        }
        _ => Err(AriesVcxError::from_msg(
            AriesVcxErrorKind::InvalidMessageFormat,
            format!("unexpected attachment type: {:?}", attach_id),
        )),
    }
}
