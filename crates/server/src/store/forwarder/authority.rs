// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::collections::HashMap;

use futures_util::{future, FutureExt};
use log::info;

use crate::client::op::LowerQuery;
use crate::client::op::ResponseCode;
use crate::client::rr::dnssec::SupportedAlgorithms;
use crate::client::rr::{LowerName, Name, Record, RecordType};
use crate::resolver::config::ResolverConfig;
use crate::resolver::error::ResolveError;
use crate::resolver::lookup::Lookup as ResolverLookup;
use crate::resolver::{TokioAsyncResolver, TokioHandle};

use crate::authority::{
    Authority, LookupError, LookupObject, MessageRequest, UpdateResult, ZoneType,
};
use crate::store::forwarder::ForwardConfig;
use crate::store::forwarder::ForwardHookConfig;

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the trust-dns-resolver for resolving requests.
pub struct ForwardAuthority {
    origin: LowerName,
    resolver: TokioAsyncResolver,
}

pub struct ForwardHookAuthority {
    origin: LowerName,
    resolver: TokioAsyncResolver, // Default resolver
    resolver_map: HashMap<String, TokioAsyncResolver>,
    acl_map: HashMap<String, String>,
}

impl ForwardAuthority {
    /// TODO: change this name to create or something
    #[allow(clippy::new_without_default)]
    #[doc(hidden)]
    pub async fn new(runtime: TokioHandle) -> Result<Self, String> {
        let resolver = TokioAsyncResolver::from_system_conf(runtime)
            .map_err(|e| format!("error constructing new Resolver: {}", e))?;

        Ok(ForwardAuthority {
            origin: Name::root().into(),
            resolver,
        })
    }

    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &ForwardConfig,
    ) -> Result<Self, String> {
        info!("loading forwarder config: {}", origin);

        let name_servers = config.name_servers.clone();
        let options = config.options.unwrap_or_default();
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let resolver = TokioAsyncResolver::new(config, options, TokioHandle)
            .map_err(|e| format!("error constructing new Resolver: {}", e))?;

        info!("forward resolver configured: {}: ", origin);

        // TODO: this might be infallible?
        Ok(ForwardAuthority {
            origin: origin.into(),
            resolver,
        })
    }
}

impl ForwardHookAuthority {
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &ForwardHookConfig,
    ) -> Result<Self, String> {
        info!("loading forwarder config: {}", origin);

        let default_name_servers = config.name_servers.clone();
        let name_servers_index = config.name_servers_index.clone();
        let options = config.options.unwrap_or_default();
        let default_config = ResolverConfig::from_parts(None, vec![], default_name_servers);
        let acls = config.acls.clone();

        let default_resolver = TokioAsyncResolver::new(default_config, options, TokioHandle)
            .map_err(|e| format!("error constructing new Resolver: {}", e))?;

        // resolver_map
        let mut resolver_map: HashMap<String, TokioAsyncResolver> = HashMap::new();
        for (key, ns) in name_servers_index.iter() {
            // println!("key: {} val: {}", key, val);
            let _config = ResolverConfig::from_parts(None, vec![], ns.clone());
            let _resolver = TokioAsyncResolver::new(_config, options, TokioHandle)
                                .map_err(|e| format!("error constructing new Resolver: {}", e))?;
            resolver_map.insert(key.clone(), _resolver);
        }

        // acl_map
        let mut acl_map: HashMap<String, String> = HashMap::new();
        for acl in acls.iter() {
            acl_map.insert(acl.name.clone(), acl.forward_to.clone());
        }

        info!("forward resolver configured: {}: ", origin);

        // TODO: this might be infallible?
        Ok(ForwardHookAuthority {
            origin: origin.into(),
            resolver: default_resolver,
            resolver_map: resolver_map,
            acl_map: acl_map,
        })
    }
}

impl Authority for ForwardAuthority {
    type Lookup = ForwardLookup;
    type LookupFuture = Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        // TODO: make this an error?
        assert!(self.origin.zone_of(name));

        info!("forwarding lookup: {} {}", name, rtype);
        let name: LowerName = name.clone();
        Box::pin(ForwardLookupFuture(self.resolver.lookup(
            name,
            rtype,
            Default::default(),
        )))
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(self.lookup(
            query.name(),
            query.query_type(),
            is_secure,
            supported_algorithms,
        ))
    }

    fn get_nsec_records(
        &self,
        _name: &LowerName,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(future::err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the forwarder",
        ))))
    }
}

impl Authority for ForwardHookAuthority {
    type Lookup = ForwardLookup;
    type LookupFuture = Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        // TODO: make this an error?
        assert!(self.origin.zone_of(name));

        info!("forwarding lookup: {} {}", name, rtype);

        // name split
        let mut labels = name.num_labels() as usize;
        let in_name = name.clone().get_name();
        while labels >= 1 {
            if let Some(resolver_name) = self.acl_map.get(&in_name.trim_to(labels).to_ascii()) {
                // TODO: unwrap not exist forwarder
                let r = self.resolver_map.get(resolver_name).unwrap();
                let name: LowerName = name.clone();
                // debug!("hit: {}", name.clone().get_name().to_utf8());
                return Box::pin(ForwardLookupFuture(r.lookup(
                    name,
                    rtype,
                    Default::default(),
                )))
            };
            labels -= 1;
        }

        let name: LowerName = name.clone();
        Box::pin(ForwardLookupFuture(self.resolver.lookup(
            name,
            rtype,
            Default::default(),
        )))
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(self.lookup(
            query.name(),
            query.query_type(),
            is_secure,
            supported_algorithms,
        ))
    }

    fn get_nsec_records(
        &self,
        _name: &LowerName,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(future::err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the forwarder",
        ))))
    }
}

pub struct ForwardLookup(ResolverLookup);

impl LookupObject for ForwardLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.record_iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}

pub struct ForwardLookupFuture<
    F: Future<Output = Result<ResolverLookup, ResolveError>> + Send + Unpin + 'static,
>(F);

impl<F: Future<Output = Result<ResolverLookup, ResolveError>> + Send + Unpin> Future
    for ForwardLookupFuture<F>
{
    type Output = Result<ForwardLookup, LookupError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.0.poll_unpin(cx) {
            Poll::Ready(Ok(f)) => Poll::Ready(Ok(ForwardLookup(f))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        }
    }
}
