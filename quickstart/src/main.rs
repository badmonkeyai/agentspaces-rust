// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The Fulfiller: one agent that ships orders, and a desk that places one.
//!
//!   cargo run              a worker: ships every order until Ctrl-C
//!   cargo run -- kite      a desk: orders a kite, prints its shipment, and exits

use std::time::Duration;

use agentspaces::agent::{HandlerError, Reply, TakeContext};
use agentspaces::space::{Fleet, Lease, Template};
use agentspaces::wire::cbor::Map;
use agentspaces::{Config, Entry};
use serde::{Deserialize, Serialize};

/// How long the desk waits for its shipment.
const WAIT: Duration = Duration::from_secs(90);

/// An order. It travels as `shop.Order#v1` with the fields `orderId` and `item`.
#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Order#v1")]
#[serde(rename_all = "camelCase")]
struct Order {
    order_id: String,
    item: String,
}

/// A shipment: what the agent makes of an order.
#[derive(Debug, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Shipment#v1")]
#[serde(rename_all = "camelCase")]
struct Shipment {
    order_id: String,
    item: String,
    by: String,
}

/// The agent's one action: an Order in, a Shipment out.
async fn ship(order: Order, ctx: TakeContext) -> Result<Reply, HandlerError> {
    println!("shipping {} (attempt {})", order.order_id, ctx.attempt());
    // keepalive renews the take while the work runs, however long it takes.
    ctx.keepalive(tokio::time::sleep(ship_time())).await;
    let shipment = Shipment {
        order_id: order.order_id,
        item: order.item,
        by: ctx.agent_id().to_owned(),
    };
    Ok(shipment.into())
}

/// How long shipping takes: no time at all, unless SHIP_SECONDS says otherwise (step 5).
fn ship_time() -> Duration {
    match std::env::var("SHIP_SECONDS") {
        Ok(seconds) => Duration::from_secs(seconds.parse().unwrap_or(0)),
        Err(_) => Duration::ZERO,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fleet = Fleet::join_config(&Config::load("fleet.yaml")?).await?;

    if let Some(item) = std::env::args().nth(1) {
        // The desk: write an order, then wait for the shipment that answers it.
        let orders = fleet.space("orders");
        let order = Order {
            order_id: format!("o-{}", std::process::id()),
            item,
        };
        orders
            .write(&order, Lease::parse("10m")?, Map::new())
            .await?;
        println!("ordered {}", order.order_id);
        let answer = format!("orderId={}", order.order_id);
        let shipped = Template::of::<Shipment>().where_clause(&answer)?;
        let shipment = orders.read_typed::<Shipment>(&shipped, WAIT).await?;
        println!("{:?}", shipment.ok_or("no shipment within 90 s")?.value());
    } else {
        // The worker: take orders, holding each for 30 s at a time, until Ctrl-C.
        let worker = fleet
            .agent("fulfiller")
            .describe("Ships orders")
            .take("orders", Lease::parse("30s")?, ship)
            .action("ship")
            .produces::<Shipment>()
            .bind()
            .await?;
        let pid = std::process::id();
        println!("serving as {} (pid {pid})", worker.agent_id());
        worker.stop_on_signals().await?;
    }

    fleet.close().await?;
    Ok(())
}
