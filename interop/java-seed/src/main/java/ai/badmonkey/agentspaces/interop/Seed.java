/*
 * Copyright 2026 Bad Monkey, Inc.
 * Author: Al Baker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.badmonkey.agentspaces.interop;

import ai.badmonkey.agentspaces.agent.AgentBinder;
import ai.badmonkey.agentspaces.agent.AgentSpaces;
import ai.badmonkey.agentspaces.agent.TakeContext;
import ai.badmonkey.agentspaces.agent.annotation.AgentSpec;
import ai.badmonkey.agentspaces.agent.annotation.SpaceTake;
import ai.badmonkey.agentspaces.agent.remote.RemoteAction;
import ai.badmonkey.agentspaces.agent.remote.RemoteActions;
import ai.badmonkey.agentspaces.api.ad.AgentCard;
import ai.badmonkey.agentspaces.api.ad.CardAction;
import ai.badmonkey.agentspaces.api.ad.GroupAdvertisement;
import ai.badmonkey.agentspaces.api.ad.PeerAdvertisement;
import ai.badmonkey.agentspaces.api.entry.EntryId;
import ai.badmonkey.agentspaces.api.space.ConflictStrategyType;
import ai.badmonkey.agentspaces.api.space.Lease;
import ai.badmonkey.agentspaces.api.error.LeaseExpiredException;
import ai.badmonkey.agentspaces.api.space.Space;
import ai.badmonkey.agentspaces.api.space.TakenEntry;
import ai.badmonkey.agentspaces.api.space.Template;
import ai.badmonkey.agentspaces.common.codec.CborCodec;
import ai.badmonkey.agentspaces.common.id.GroupId;
import ai.badmonkey.agentspaces.discovery.DiscoveryService;
import ai.badmonkey.agentspaces.identity.PeerIdentity;
import ai.badmonkey.agentspaces.peering.membership.GroupMembership;
import ai.badmonkey.agentspaces.peering.node.GroupRuntime;
import ai.badmonkey.agentspaces.peering.blocks.BlockExchange;
import ai.badmonkey.agentspaces.peering.node.PeerNode;
import ai.badmonkey.agentspaces.peering.transport.TcpTransport;
import ai.badmonkey.agentspaces.peering.transport.TlsTcpTransport;
import ai.badmonkey.agentspaces.space.replicated.ReplicatedSpace;
import ai.badmonkey.agentspaces.space.replicated.TakeClaim;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A scripted Java seed for the Rust interop tests. It founds a group from a founding text,
 * listens on {@code tcp} or {@code tls}, keeps one replicated space, and answers commands read
 * from standard input, one per line, with one JSON object per line on standard output:
 *
 * <pre>
 *   members                        {"members":["z...", ...]}
 *   write-task TOPIC PRIORITY      {"written":"TOPIC"}
 *   tasks                          {"tasks":[{"topic":..,"priority":..}, ...]}
 *   results                        {"results":[{"topic":..,"summary":..,"worker":..}, ...]}
 *   take-task TIMEOUT_MS WORKER    {"took":"TOPIC"} or {"took":null}  (completes with a Result)
 *   take-all IDLE_MS WORKER        {"took":["TOPIC", ...],"lost":["TOPIC", ...]}  (take-task until
 *                                  a take finds nothing for IDLE_MS; "lost" lists the takes whose
 *                                  completion found the hold lapsed or lost)
 *   entries                        {"entries":[{"entryId":..,"topic":..,"priority":..,"issuer":..,
 *                                  "attestation":"PEER_ASSERTED"|"AGENT_ATTESTED"}, ...]}
 *   sizes                          {"sizes":[{"entryId":..,"topicLength":n,"head":..,"priority":..},
 *                                  ...]}  (the tasks this replica can read, with the length of
 *                                  each topic and its first 16 characters: a task whose payload
 *                                  travelled as a block is listed once the block is held here)
 *   task-state TOPIC               {"topic":..,"entryId":..|null,"state":"available"|"claimed"|
 *                                  "completed"|"gone"|"unknown","holder":..|null,"epoch":n|null,
 *                                  "claimLive":bool,"events":["WRITTEN by AGENT", ...]}
 *   task-states                    {"states":[ the task-state of every topic seen, ... ]}
 *   write-long-task UNITS PRIORITY [TAG_UNITS]
 *                                  {"written":{"entryId":..,"topicUnits":n,"topicSha256":..,
 *                                  "tagUnits":n|null,"tagSha256":..|null}}  writes
 *                                  Task(longText("topic:", UNITS), PRIORITY), tagged
 *                                  note=longText("tag-v:", TAG_UNITS) when TAG_UNITS is given
 *                                  ({@link #longText}: non-ASCII text with surrogate pairs, the
 *                                  same text the Rust tests build)
 *   long-texts                     {"tasks":[{"entryId":..,"topicUnits":n,"topicSha256":..,
 *                                  "priority":n,"issuer":..,"tags":{"KEY":{"units":n,"sha256":..},
 *                                  ..}}, ...],"results":[{"entryId":..,"topicUnits":n,
 *                                  "topicSha256":..,"summaryUnits":n,"summarySha256":..,
 *                                  "worker":..,"tags":{..}}, ...]}  (every task and result this
 *                                  replica reads, each text as its UTF-16 length and the SHA-256
 *                                  of its UTF-8 bytes in hex)
 *   write-priced ITEM AMOUNT SERIAL
 *                                  {"written":{"entryId":..}}  writes Priced(ITEM,
 *                                  new BigDecimal(AMOUNT), new BigInteger(SERIAL)): the codec writes
 *                                  the decimal as tag 4 and a serial outside a long as a bignum
 *   priced                         {"priced":[{"entryId":..,"item":..,"amount":..,"serial":..,
 *                                  "issuer":..}, ...]}  (every Priced this replica reads, its
 *                                  amount and serial as BigDecimal and BigInteger print them)
 *   frames                         {"signed":n,"bare":n,"session":n}
 *   links                          {"links":[{"peer":..,"scheme":"tcp"|"tls"|"?","mode":..}, ...]}
 *                                  (each connected peer's transport scheme and channel mode, as
 *                                  example 02's printLinks reads them; "tls" + "attested" is a
 *                                  link whose CHANNEL_HELLO arrived on a channel the handshake
 *                                  attested)
 *   cards                          {"cards":[{"agent":..,"issuer":..,"attested":bool,"certified":bool,
 *                                  "actions":[{"name":..,"kind":..,"space":..,"consumes":[..],
 *                                  "produces":[..]}, ...]}, ...]}  (the AgentCards the seed's
 *                                  DiscoveryService admitted: verified, live, unrevoked; each
 *                                  card also carries "description", "goals", "consumes",
 *                                  "produces", "spaceBindings", "agentKey" (bool), and each action
 *                                  its "description")
 *   bind-agent NAME [peer-signed] [DELAY_MS]
 *                                  {"bound":"PEER/NAME","signing":"subordinate"|"peer"}  binds a
 *                                  {@link JavaResearcher} as agent NAME through the AgentSpaces
 *                                  facade (AgentBinder): its {@code @SpaceTake research(Task)} takes
 *                                  tasks from the seed's space and completes each with
 *                                  Result(topic, "researched in java: TOPIC", PEER/NAME) after
 *                                  DELAY_MS (0 by default); the binder publishes its AgentCard.
 *                                  The agent signs with a renewing subordinate key (24 h
 *                                  certificates) unless "peer-signed" says it signs as the peer.
 *   bind-reviewer NAME [DELAY_MS]  {"bound":"PEER/NAME","signing":"subordinate"}  binds a
 *                                  {@link JavaReviewer} as agent NAME: its {@code @SpaceTake
 *                                  review(Draft)} takes drafts from the seed's space and completes
 *                                  each with Verdict(topic, "reviewed in java: TOPIC", PEER/NAME)
 *                                  after DELAY_MS (0 by default); its card declares the one take
 *                                  action {@code review}, an action no {@code bind-agent} offers,
 *                                  so binding it changes the fleet's catalogue
 *   unbind-agent NAME              {"unbound":"PEER/NAME"}  closes the binding (takes nothing new),
 *                                  of an agent bound by either command
 *   remote-actions                 {"actions":[{"name":..,"declared":..,"kind":..,"agent":..,
 *                                  "issuer":..,"input":..,"output":..,"space":..,"resultSpace":..,
 *                                  "description":..,"consumes":[..],"produces":[..]}, ...]}  (Java
 *                                  RemoteActions.available(): foreign cards whose schemas resolve to
 *                                  classes here, newest first; "input"/"output" are class names)
 *   invoke SELECTOR TOPIC PRIORITY TIMEOUT_MS
 *                                  {"action":..,"agent":..,"result":{"topic":..,"summary":..,
 *                                  "worker":..}|null}  invokes, through RemoteAction.invoke, the
 *                                  first available action consuming Task and producing Result
 *                                  whose declared name, planner name, agent, or agent local name is
 *                                  SELECTOR, with Task(TOPIC, PRIORITY); null at the timeout
 *   quit                           exits
 * </pre>
 *
 * <p>The seed learns each task's entry id from its own writes and from the events of a notify
 * subscription on {@code Task} it holds from the start (which also records each task's
 * transitions with their actors, for {@code task-state}).
 *
 * Arguments: {@code port [--tls] [--require-attestation] [--channel-auth SIGNED|ATTESTED|SESSION]
 * [--founding TEXT] [--space NAME] [--settle-ms N] [--blocks] [--dial HOST:PORT]}. {@code --blocks}
 * gives the space a {@link BlockExchange}, as the Spring starter does: payloads over the inline
 * limit (64 KiB) are fetched from their writer in the background and held and served here. The
 * first line printed is
 * {@code {"event":"listening","port":..,"peer":"..","group":"..","space":".."}}.
 *
 * <p>With {@code --dial HOST:PORT} the node listens nowhere: it registers the {@code tcp} (or, with
 * {@code --tls}, the {@code tls}) binding for dialing and joins the group through that seed, a
 * listening member of another implementation, introducing itself there as a member does (the port
 * argument is then ignored). Every command works the same. The first line printed is then
 * {@code {"event":"dialing","seed":"HOST:PORT","peer":"..","group":"..","space":".."}}.
 */
public final class Seed {

    /** A task, as the Rust tests write and read it. */
    public record Task(String topic, int priority) {
    }

    /** A result, as a worker completes a task with it. */
    public record Result(String topic, String summary, String worker) {
    }

    /** A draft, as the {@code review} action takes it. */
    public record Draft(String topic, int priority) {
    }

    /** A verdict, as a reviewer completes a draft with it. */
    public record Verdict(String topic, String verdict, String reviewer) {
    }

    /** A priced item: a Java BigDecimal and BigInteger on the wire (tags 4, 2 and 3). */
    public record Priced(String item, BigDecimal amount, BigInteger serial) {
    }

    /**
     * A second Java agent ({@code bind-reviewer}): its card declares the one take action
     * {@code review}, consuming {@link Draft} and producing {@link Verdict}, in the seed's sole
     * space.
     */
    @AgentSpec(name = "java-reviewer", description = "Reviews drafts in Java", goals = {"review a draft"})
    public static final class JavaReviewer {

        private final long delayMs;

        JavaReviewer(long delayMs) {
            this.delayMs = delayMs;
        }

        /**
         * Reviews one draft: completes it with a verdict naming the agent that took it.
         *
         * @param draft the draft taken
         * @return the verdict
         */
        @SpaceTake(lease = "30s", description = "Reviews a draft in Java")
        public Verdict review(Draft draft) {
            if (delayMs > 0) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("interrupted", e);
                }
            }
            String reviewer = TakeContext.current().map(context -> context.agent().encoded())
                    .orElse("java-agent");
            return new Verdict(draft.topic(), "reviewed in java: " + draft.topic(), reviewer);
        }
    }

    /**
     * A Java agent bound through the AgentSpaces facade ({@code bind-agent}): its card declares the
     * one take action {@code research}, consuming {@link Task} and producing {@link Result}, in the
     * seed's sole space.
     */
    @AgentSpec(name = "java-researcher", description = "Researches tasks in Java",
            goals = {"research a topic"})
    public static final class JavaResearcher {

        private final long delayMs;

        JavaResearcher(long delayMs) {
            this.delayMs = delayMs;
        }

        /**
         * Researches one task: completes it with a result naming the agent that took it.
         *
         * @param task the task taken
         * @return the result
         */
        @SpaceTake(lease = "30s", description = "Researches a task in Java")
        public Result research(Task task) {
            if (delayMs > 0) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("interrupted", e);
                }
            }
            String worker = TakeContext.current().map(context -> context.agent().encoded())
                    .orElse("java-agent");
            return new Result(task.topic(), "researched in java: " + task.topic(), worker);
        }
    }

    private Seed() {
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        boolean tls = false;
        boolean require = false;
        PeerNode.ChannelAuth auth = PeerNode.ChannelAuth.SIGNED;
        String founding = "agentspaces-rust-interop-v1";
        String spaceName = "tasks";
        long settleMs = 200;
        boolean withBlocks = false;
        String dial = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--tls" -> tls = true;
                case "--require-attestation" -> require = true;
                case "--channel-auth" -> auth = PeerNode.ChannelAuth.valueOf(args[++i]);
                case "--founding" -> founding = args[++i];
                case "--space" -> spaceName = args[++i];
                case "--settle-ms" -> settleMs = Long.parseLong(args[++i]);
                case "--blocks" -> withBlocks = true;
                case "--dial" -> dial = args[++i];
                default -> throw new IllegalArgumentException("unknown argument " + args[i]);
            }
        }
        PeerIdentity identity = PeerIdentity.generate();
        PeerNode node = PeerNode.builder(identity).requireAttestation(require).channelAuth(auth).build();
        List<PeerAdvertisement.Endpoint> seeds = List.of();
        if (dial == null) {
            node.listen(tls ? new TlsTcpTransport(identity) : new TcpTransport(), "127.0.0.1:" + port);
        } else {
            node.transport(tls ? new TlsTcpTransport(identity) : new TcpTransport());
            seeds = List.of(new PeerAdvertisement.Endpoint(tls ? "tls" : "tcp", dial, 0));
        }
        GroupId groupId = GroupId.fromFounding(founding.getBytes(StandardCharsets.UTF_8));
        GroupAdvertisement group = new GroupAdvertisement("aspace://" + groupId.value(),
                identity.peerId(), groupId, Instant.EPOCH, Duration.ofDays(365), "rust-interop",
                GroupAdvertisement.MembershipPolicy.OPEN, ConflictStrategyType.LEASE_RACE,
                GroupAdvertisement.GossipParameters.defaults());
        GroupRuntime runtime = node.joinGroup(group,
                new GroupMembership.Config(Duration.ofSeconds(30), Duration.ofSeconds(2), 2),
                seeds);
        // The group's discovery service: it admits the AgentCards members publish on the ads
        // stream as every Java node does (AdCache.accept), for the cards command.
        DiscoveryService discovery = DiscoveryService.create(runtime, CborCodec.defaultCodec(),
                identity.peerId(), InstantSource.system(), Set.of());
        ReplicatedSpace.Builder spaceBuilder = ReplicatedSpace.builder(runtime, spaceName, identity, "java-seed")
                .settleWindow(Duration.ofMillis(settleMs));
        if (withBlocks) {
            spaceBuilder.blocks(new BlockExchange(runtime, CborCodec.defaultCodec()));
        }
        ReplicatedSpace space = spaceBuilder.build();
        // The Java worker layer over the same group and space (bind-agent, remote-actions, invoke):
        // agents sign with renewing subordinate keys, as the Spring starter mints them, unless
        // bound peer-signed.
        Set<String> peerSigned = ConcurrentHashMap.newKeySet();
        AgentSpaces agents = new AgentSpaces(identity, InstantSource.system(), name -> peerSigned.contains(name)
                ? identity.agentIdentity(name)
                : identity.renewingSubordinate(name, Duration.ofHours(24), InstantSource.system()));
        AgentSpaces.GroupContext groupContext = agents.register("rust-interop", groupId, runtime, discovery)
                .space(spaceName, space);
        RemoteActions remote = RemoteActions.over(groupContext, identity.peerId());
        Map<String, AgentBinder.Bound> boundAgents = new ConcurrentHashMap<>();
        // Every task's entry id by topic, and its transitions with their actors, for task-state.
        Map<String, EntryId> taskIds = new ConcurrentHashMap<>();
        Map<String, List<String>> taskEvents = new ConcurrentHashMap<>();
        space.notify(Template.of(Task.class), event -> {
            String topic = event.entry().topic();
            taskIds.putIfAbsent(topic, event.entryId());
            taskEvents.computeIfAbsent(topic, t -> java.util.Collections.synchronizedList(new ArrayList<>()))
                    .add(event.kind() + " by " + event.actor().encoded());
        }, Lease.of(Duration.ofDays(1)));
        node.startTicking(Duration.ofMillis(250));
        if (dial == null) {
            System.out.println("{\"event\":\"listening\",\"port\":" + port + ",\"peer\":" + q(identity.peerId().value())
                    + ",\"group\":" + q(groupId.value()) + ",\"space\":" + q(spaceName) + ",\"tls\":" + tls + "}");
        } else {
            System.out.println("{\"event\":\"dialing\",\"seed\":" + q(dial) + ",\"peer\":" + q(identity.peerId().value())
                    + ",\"group\":" + q(groupId.value()) + ",\"space\":" + q(spaceName) + ",\"tls\":" + tls + "}");
        }
        System.out.flush();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            String[] cmd = line.trim().split("\\s+", 3);
            if (cmd.length == 0 || cmd[0].isEmpty()) {
                continue;
            }
            try {
                switch (cmd[0]) {
                    case "members" -> {
                        StringBuilder out = new StringBuilder("{\"members\":[");
                        runtime.membership().allMembers().stream()
                                .filter(m -> !m.id().equals(identity.peerId()))
                                .forEach(m -> out.append(q(m.id().value())).append(','));
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "write-task" -> {
                        EntryId written = space.write(new Task(cmd[1], Integer.parseInt(cmd[2])),
                                Lease.of(Duration.ofMinutes(30))).entryId();
                        taskIds.put(cmd[1], written);
                        System.out.println("{\"written\":" + q(cmd[1]) + "}");
                    }
                    case "tasks" -> {
                        StringBuilder out = new StringBuilder("{\"tasks\":[");
                        for (Task t : space.readAll(Template.of(Task.class), 1000)) {
                            out.append("{\"topic\":").append(q(t.topic())).append(",\"priority\":")
                                    .append(t.priority()).append("},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "results" -> {
                        StringBuilder out = new StringBuilder("{\"results\":[");
                        for (Result r : space.readAll(Template.of(Result.class), 1000)) {
                            out.append("{\"topic\":").append(q(r.topic())).append(",\"summary\":")
                                    .append(q(r.summary())).append(",\"worker\":").append(q(r.worker())).append("},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "take-task" -> {
                        long timeout = Long.parseLong(cmd[1]);
                        String worker = cmd.length > 2 ? cmd[2] : "java-seed";
                        Optional<TakenEntry<Task>> taken = space.take(Template.of(Task.class),
                                Lease.of(Duration.ofSeconds(30)), Duration.ofMillis(timeout));
                        if (taken.isPresent()) {
                            Task t = taken.get().entry();
                            space.complete(taken.get(), new Result(t.topic(), "done by java", worker),
                                    Lease.of(Duration.ofHours(1)));
                            System.out.println("{\"took\":" + q(t.topic()) + "}");
                        } else {
                            System.out.println("{\"took\":null}");
                        }
                    }
                    case "take-all" -> {
                        long idle = Long.parseLong(cmd[1]);
                        String worker = cmd.length > 2 ? cmd[2] : "java-seed";
                        StringBuilder took = new StringBuilder("{\"took\":[");
                        StringBuilder lost = new StringBuilder("\"lost\":[");
                        while (true) {
                            Optional<TakenEntry<Task>> taken = space.take(Template.of(Task.class),
                                    Lease.of(Duration.ofSeconds(30)), Duration.ofMillis(idle));
                            if (taken.isEmpty()) {
                                break;
                            }
                            Task t = taken.get().entry();
                            try {
                                space.complete(taken.get(), new Result(t.topic(), "done by java", worker),
                                        Lease.of(Duration.ofHours(1)));
                                took.append(q(t.topic())).append(',');
                            } catch (LeaseExpiredException e) {
                                lost.append(q(t.topic())).append(',');
                            }
                        }
                        trim(took).append("],");
                        trim(lost).append("]}");
                        System.out.println(took.append(lost));
                    }
                    case "entries" -> {
                        StringBuilder out = new StringBuilder("{\"entries\":[");
                        for (Space.Entry<Task> e : space.readAllEntries(Template.of(Task.class), 1000)) {
                            taskIds.putIfAbsent(e.value().topic(), e.entryId());
                            out.append("{\"entryId\":").append(q(e.entryId().value()))
                                    .append(",\"topic\":").append(q(e.value().topic()))
                                    .append(",\"priority\":").append(e.value().priority())
                                    .append(",\"issuer\":").append(q(e.issuer().encoded()))
                                    .append(",\"attestation\":").append(q(e.attestation().name())).append("},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "sizes" -> {
                        StringBuilder out = new StringBuilder("{\"sizes\":[");
                        for (Space.Entry<Task> e : space.readAllEntries(Template.of(Task.class), 1000)) {
                            String topic = e.value().topic();
                            out.append("{\"entryId\":").append(q(e.entryId().value()))
                                    .append(",\"topicLength\":").append(topic.length())
                                    .append(",\"head\":").append(q(topic.substring(0, Math.min(16, topic.length()))))
                                    .append(",\"priority\":").append(e.value().priority()).append("},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "write-long-task" -> {
                        String[] words = line.trim().split("\\s+");
                        String topic = longText("topic:", Integer.parseInt(words[1]));
                        String tag = words.length > 3 ? longText("tag-v:", Integer.parseInt(words[3])) : null;
                        EntryId written = space.write(new Task(topic, Integer.parseInt(words[2])),
                                Lease.of(Duration.ofMinutes(30)), tag == null ? Map.of() : Map.of("note", tag))
                                .entryId();
                        taskIds.put(topic, written);
                        System.out.println("{\"written\":{\"entryId\":" + q(written.value())
                                + ",\"topicUnits\":" + topic.length() + ",\"topicSha256\":" + q(sha256(topic))
                                + ",\"tagUnits\":" + (tag == null ? "null" : String.valueOf(tag.length()))
                                + ",\"tagSha256\":" + (tag == null ? "null" : q(sha256(tag))) + "}}");
                    }
                    case "long-texts" -> {
                        StringBuilder out = new StringBuilder("{\"tasks\":[");
                        for (Space.Entry<Task> e : space.readAllEntries(Template.of(Task.class), 1000)) {
                            out.append("{\"entryId\":").append(q(e.entryId().value()))
                                    .append(",\"topicUnits\":").append(e.value().topic().length())
                                    .append(",\"topicSha256\":").append(q(sha256(e.value().topic())))
                                    .append(",\"priority\":").append(e.value().priority())
                                    .append(",\"issuer\":").append(q(e.issuer().encoded()))
                                    .append(",\"tags\":").append(textDigests(e.tags())).append("},");
                        }
                        trim(out).append("],\"results\":[");
                        for (Space.Entry<Result> e : space.readAllEntries(Template.of(Result.class), 1000)) {
                            Result r = e.value();
                            out.append("{\"entryId\":").append(q(e.entryId().value()))
                                    .append(",\"topicUnits\":").append(r.topic().length())
                                    .append(",\"topicSha256\":").append(q(sha256(r.topic())))
                                    .append(",\"summaryUnits\":").append(r.summary().length())
                                    .append(",\"summarySha256\":").append(q(sha256(r.summary())))
                                    .append(",\"worker\":").append(q(r.worker()))
                                    .append(",\"tags\":").append(textDigests(e.tags())).append("},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "write-priced" -> {
                        String[] words = line.trim().split("\\s+");
                        EntryId written = space.write(new Priced(words[1], new BigDecimal(words[2]),
                                new BigInteger(words[3])), Lease.of(Duration.ofMinutes(30))).entryId();
                        System.out.println("{\"written\":{\"entryId\":" + q(written.value()) + "}}");
                    }
                    case "priced" -> {
                        StringBuilder out = new StringBuilder("{\"priced\":[");
                        for (Space.Entry<Priced> e : space.readAllEntries(Template.of(Priced.class), 1000)) {
                            out.append("{\"entryId\":").append(q(e.entryId().value()))
                                    .append(",\"item\":").append(q(e.value().item()))
                                    .append(",\"amount\":").append(q(e.value().amount().toString()))
                                    .append(",\"serial\":").append(q(e.value().serial().toString()))
                                    .append(",\"issuer\":").append(q(e.issuer().encoded())).append("},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "task-state" -> System.out.println(taskState(space, cmd[1], taskIds, taskEvents));
                    case "task-states" -> {
                        StringBuilder out = new StringBuilder("{\"states\":[");
                        for (String topic : new java.util.TreeSet<>(taskIds.keySet())) {
                            out.append(taskState(space, topic, taskIds, taskEvents)).append(',');
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "cards" -> {
                        StringBuilder out = new StringBuilder("{\"cards\":[");
                        for (AgentCard c : discovery.find(AgentCard.class, card -> true)) {
                            out.append("{\"agent\":").append(q(c.agent().encoded()))
                                    .append(",\"issuer\":").append(q(c.issuer().value()))
                                    .append(",\"attested\":").append(c.attested())
                                    .append(",\"certified\":").append(c.agentCertificate() != null)
                                    .append(",\"agentKey\":").append(c.agentPublicKey() != null)
                                    .append(",\"description\":").append(q(String.valueOf(c.description())))
                                    .append(",\"goals\":").append(texts(c.goals()))
                                    .append(",\"consumes\":").append(texts(c.consumes()))
                                    .append(",\"produces\":").append(texts(c.produces()))
                                    .append(",\"spaceBindings\":{");
                            if (c.spaceBindings() != null) {
                                c.spaceBindings().forEach((schema, bound) ->
                                        out.append(q(schema)).append(':').append(q(bound)).append(','));
                            }
                            trim(out).append("},\"actions\":[");
                            if (c.actions() != null) {
                                for (CardAction a : c.actions()) {
                                    out.append("{\"name\":").append(q(a.name()))
                                            .append(",\"kind\":").append(q(a.kind()))
                                            .append(",\"space\":").append(a.space() == null ? "null" : q(a.space()))
                                            .append(",\"description\":").append(q(String.valueOf(a.description())))
                                            .append(",\"consumes\":").append(texts(a.consumes()))
                                            .append(",\"produces\":").append(texts(a.produces())).append("},");
                                }
                            }
                            trim(out).append("]},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "bind-agent" -> {
                        String[] words = line.trim().split("\\s+");
                        String name = words[1];
                        boolean peer = Arrays.asList(words).contains("peer-signed");
                        long delay = Arrays.stream(words).skip(2).filter(w -> w.matches("\\d+"))
                                .mapToLong(Long::parseLong).findFirst().orElse(0L);
                        if (boundAgents.containsKey(name)) {
                            throw new IllegalStateException("agent " + name + " is already bound");
                        }
                        if (peer) {
                            peerSigned.add(name);
                        }
                        AgentBinder.Bound bound = groupContext.bind(new JavaResearcher(delay), name);
                        boundAgents.put(name, bound);
                        System.out.println("{\"bound\":" + q(bound.agentId().encoded()) + ",\"signing\":"
                                + q(peer ? "peer" : "subordinate") + "}");
                    }
                    case "bind-reviewer" -> {
                        String[] words = line.trim().split("\\s+");
                        String name = words[1];
                        long delay = words.length > 2 ? Long.parseLong(words[2]) : 0L;
                        if (boundAgents.containsKey(name)) {
                            throw new IllegalStateException("agent " + name + " is already bound");
                        }
                        AgentBinder.Bound bound = groupContext.bind(new JavaReviewer(delay), name);
                        boundAgents.put(name, bound);
                        System.out.println("{\"bound\":" + q(bound.agentId().encoded())
                                + ",\"signing\":\"subordinate\"}");
                    }
                    case "unbind-agent" -> {
                        AgentBinder.Bound bound = boundAgents.remove(cmd[1]);
                        if (bound == null) {
                            throw new IllegalStateException("no agent " + cmd[1] + " is bound");
                        }
                        bound.close();
                        System.out.println("{\"unbound\":" + q(bound.agentId().encoded()) + "}");
                    }
                    case "remote-actions" -> {
                        StringBuilder out = new StringBuilder("{\"actions\":[");
                        for (RemoteAction a : remote.available()) {
                            out.append("{\"name\":").append(q(a.name()))
                                    .append(",\"declared\":").append(a.declared().map(d -> q(d.name())).orElse("null"))
                                    .append(",\"kind\":").append(a.declared().map(d -> q(d.kind())).orElse("null"))
                                    .append(",\"agent\":").append(q(a.card().agent().encoded()))
                                    .append(",\"issuer\":").append(q(a.card().issuer().value()))
                                    .append(",\"input\":").append(q(a.inputType().getName()))
                                    .append(",\"output\":").append(q(a.outputType().getName()))
                                    .append(",\"space\":").append(q(a.taskSpace().name()))
                                    .append(",\"resultSpace\":").append(q(a.resultSpace().name()))
                                    .append(",\"description\":").append(q(a.description()))
                                    .append(",\"consumes\":").append(a.declared().map(d -> texts(d.consumes())).orElse("null"))
                                    .append(",\"produces\":").append(a.declared().map(d -> texts(d.produces())).orElse("null"))
                                    .append("},");
                        }
                        trim(out).append("]}");
                        System.out.println(out);
                    }
                    case "invoke" -> {
                        String[] words = line.trim().split("\\s+");
                        String selector = words[1];
                        Task input = new Task(words[2], Integer.parseInt(words[3]));
                        Duration timeout = Duration.ofMillis(Long.parseLong(words[4]));
                        List<RemoteAction> available = remote.available();
                        RemoteAction action = available.stream()
                                .filter(a -> a.inputType() == Task.class && a.outputType() == Result.class)
                                .filter(a -> selector.equals(a.name())
                                        || a.declared().map(d -> selector.equals(d.name())).orElse(false)
                                        || selector.equals(a.card().agent().encoded())
                                        || selector.equals(a.card().agent().localName()))
                                .findFirst()
                                .orElseThrow(() -> new IllegalStateException("no remote action matches "
                                        + selector + "; available: " + available));
                        Optional<Result> result = action.invoke(input, Result.class, timeout);
                        System.out.println("{\"action\":" + q(action.name()) + ",\"agent\":"
                                + q(action.card().agent().encoded()) + ",\"result\":"
                                + result.map(r -> "{\"topic\":" + q(r.topic()) + ",\"summary\":" + q(r.summary())
                                        + ",\"worker\":" + q(r.worker()) + "}").orElse("null") + "}");
                    }
                    case "frames" -> System.out.println("{\"signed\":" + node.signedFramesSent() + ",\"bare\":"
                            + node.bareFramesSent() + ",\"session\":" + node.sessionFramesSent() + "}");
                    case "links" -> {
                        Map<ai.badmonkey.agentspaces.common.id.PeerId, String> modes = node.channelModes();
                        Map<String, String> links = new java.util.TreeMap<>();
                        node.connectionSchemes().forEach((peer, scheme) -> links.put(peer.value(),
                                "{\"peer\":" + q(peer.value()) + ",\"scheme\":" + q(scheme)
                                        + ",\"mode\":" + q(modes.getOrDefault(peer, "?")) + "}"));
                        System.out.println("{\"links\":[" + String.join(",", links.values()) + "]}");
                    }
                    case "quit" -> {
                        agents.close();
                        space.close();
                        node.close();
                        System.out.println("{\"bye\":true}");
                        System.out.flush();
                        System.exit(0);
                    }
                    default -> System.out.println("{\"error\":" + q("unknown command " + cmd[0]) + "}");
                }
            } catch (RuntimeException e) {
                System.out.println("{\"error\":" + q(String.valueOf(e)) + "}");
            }
            System.out.flush();
        }
        agents.close();
        space.close();
        node.close();
    }

    /**
     * What this replica holds of the task {@code topic}: its entry id, whether it is available,
     * claimed (a live claim), completed, or gone (withdrawn), the claim in force (its holder and
     * epoch, kept after a completion), and the transitions the seed's subscription saw.
     */
    private static String taskState(ReplicatedSpace space, String topic, Map<String, EntryId> taskIds,
                                    Map<String, List<String>> taskEvents) {
        StringBuilder out = new StringBuilder("{\"topic\":").append(q(topic));
        EntryId id = taskIds.get(topic);
        if (id == null) {
            out.append(",\"entryId\":null,\"state\":\"unknown\",\"holder\":null,\"epoch\":null,"
                    + "\"claimLive\":false");
        } else {
            boolean present = space.recordOf(id).isPresent();
            boolean completed = !present && space.recordOf(id, true).isPresent();
            Optional<TakeClaim> claim = space.currentClaim(id);
            boolean live = claim.isPresent() && !claim.get().expired(System.currentTimeMillis());
            String state = completed ? "completed" : !present ? "gone" : live ? "claimed" : "available";
            out.append(",\"entryId\":").append(q(id.value()))
                    .append(",\"state\":").append(q(state))
                    .append(",\"holder\":").append(claim.map(c -> q(c.holder().encoded())).orElse("null"))
                    .append(",\"epoch\":").append(claim.map(c -> String.valueOf(c.epoch())).orElse("null"))
                    .append(",\"claimLive\":").append(live);
        }
        out.append(",\"events\":[");
        List<String> events = taskEvents.getOrDefault(topic, List.of());
        synchronized (events) {
            for (String event : events) {
                out.append(q(event)).append(',');
            }
        }
        return trim(out).append("]}").toString();
    }

    /** The pieces {@link #longText} cycles through: twelve UTF-16 units, every UTF-8 width. */
    private static final String[] PIECES = {"t", "o", "p", "é", "中", "😀", "-", "€",
        "𝄞", "x"};

    /**
     * A deterministic text of exactly {@code units} UTF-16 units: the code points of
     * {@code prefix}, then {@link #PIECES} over and over, a {@code z} where a surrogate pair would
     * overshoot. The Rust interop tests build the same text. After the six units of
     * {@code "topic:"} a high surrogate falls on unit 3995, so Jackson's first chunk of such a
     * topic takes 3995 units.
     */
    static String longText(String prefix, int units) {
        List<String> head = prefix.codePoints().mapToObj(Character::toString).toList();
        StringBuilder out = new StringBuilder(units);
        for (int i = 0; out.length() < units; i++) {
            String piece = i < head.size() ? head.get(i) : PIECES[(i - head.size()) % PIECES.length];
            out.append(out.length() + piece.length() > units ? "z" : piece);
        }
        return out.toString();
    }

    /** The SHA-256 of a text's UTF-8 bytes, in lowercase hex. */
    private static String sha256(String text) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Tags as {"KEY":{"units":n,"sha256":..}, ...}, keys in their own order. */
    private static String textDigests(Map<String, String> tags) {
        StringBuilder out = new StringBuilder("{");
        if (tags != null) {
            new java.util.TreeMap<>(tags).forEach((key, value) -> out.append(q(key)).append(":{\"units\":")
                    .append(value.length()).append(",\"sha256\":").append(q(sha256(value))).append("},"));
        }
        return trim(out).append('}').toString();
    }

    private static StringBuilder trim(StringBuilder out) {
        if (out.charAt(out.length() - 1) == ',') {
            out.setLength(out.length() - 1);
        }
        return out;
    }

    private static String texts(List<String> items) {
        StringBuilder out = new StringBuilder("[");
        if (items == null) {
            return "[]";
        }
        items.forEach(item -> out.append(q(item)).append(','));
        return trim(out).append(']').toString();
    }

    private static String q(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
