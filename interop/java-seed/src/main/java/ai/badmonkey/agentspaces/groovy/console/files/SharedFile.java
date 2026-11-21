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
package ai.badmonkey.agentspaces.groovy.console.files;

/**
 * A copy of the Groovy console's file-share metadata record, under the console's fully qualified
 * name so the wire type is the console's ({@code ...console.files.SharedFile#v1}): the seed shares
 * files the way the console's Add to space does.
 */
public record SharedFile(String location, String key, String name, String root, long size, String mediaType, long sharedAt) {}
