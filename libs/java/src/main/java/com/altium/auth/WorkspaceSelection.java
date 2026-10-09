package com.altium.auth;

import java.util.Locale;

/** Whether {@code /connect/authorize} lets the user pick a workspace (SPEC §3.1). */
public enum WorkspaceSelection {
    /** No workspace selection; the parameter is omitted and the flow issues a global token. */
    NONE,
    /** Workspace selection is mandatory. */
    STRICT,
    /** Workspace selection is offered but may be skipped. */
    OPTIONAL;

    /** The {@code selectWorkspace} query value. */
    public String value() {
        return name().toLowerCase(Locale.ROOT);
    }
}
