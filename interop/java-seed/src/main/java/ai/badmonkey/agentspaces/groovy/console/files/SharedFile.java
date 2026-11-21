/* Copyright 2026 Bad Monkey, Inc. Licensed under the Apache License, Version 2.0. */
package ai.badmonkey.agentspaces.groovy.console.files;

/**
 * A copy of the Groovy console's file-share metadata record, under the console's fully qualified
 * name so the wire type is the console's ({@code ...console.files.SharedFile#v1}): the seed shares
 * files the way the console's Add to space does.
 */
public record SharedFile(String location, String key, String name, String root, long size, String mediaType, long sharedAt) {}
