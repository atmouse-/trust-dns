// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Deserialize;

use crate::resolver::config::{NameServerConfigGroup, ResolverOpts};
use crate::resolver::config::{AclEntry, NameServerHookAclGroup};
use std::collections::HashMap;

/// Configuration for file based zones
#[derive(Deserialize, PartialEq, Debug)]
pub struct ForwardConfig {
    /// upstream name_server configurations
    pub name_servers: NameServerConfigGroup,
    /// Resolver options
    pub options: Option<ResolverOpts>,
}

#[derive(Deserialize, PartialEq, Debug)]
pub struct ForwardHookConfig {
    /// upstream name_server configurations
    pub name_servers: NameServerConfigGroup,
    pub name_servers_index: HashMap<String, NameServerConfigGroup>,
    pub acls: Vec<AclEntry>,
    /// Resolver options
    pub options: Option<ResolverOpts>,
}
