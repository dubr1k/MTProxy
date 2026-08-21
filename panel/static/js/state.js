export function createPanelState() {
  return {
    view: "dashboard",
    navigationGeneration: 0,
    me: null,
    users: [],
    userFilter: "all",
    userQuery: "",
    mieruUsers: [],
    mieruService: { ready: false, revision: "" },
    naiveUsers: [],
    naiveService: { ready: false, host: "" },
    naiveFilter: "all",
    naiveQuery: "",
    versions: { enabled: false, components: {} },
    fleet: [],
    fleetSelection: "",
    fleetCommands: [],
    admins: [],
    audit: {
      items: [],
      nextCursor: null,
      actor: "",
      action: "",
      target: "",
    },
  };
}

export function isCurrent(state, generation, viewName) {
  return state.navigationGeneration === generation && state.view === viewName;
}
