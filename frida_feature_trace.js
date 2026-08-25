/*
 * KakaoTalk 26.7.1 / authorized binary assessment
 * General runtime-evidence tracer:
 *   user action -> screen/lifecycle -> observable state -> network -> response/push
 *
 * Every [TRACE] record includes a runId, evidenceRef, observation status,
 * current UI context, and the common security-card fields it can support.
 * A feature name is deliberately not assigned here: feature grouping and
 * security interpretation belong in a deterministic post-processor/LLM step.
 *
 * Frida RPC (for an MCP/host controller):
 *   get_common_summary()  -> returns a value-free, de-duplicated run summary
 *   emit_common_summary() -> also prints that summary as one [COMMON] record
 *   reset_common_summary(label) -> starts a new action/scenario summary segment
 * In the interactive Frida REPL, printCommonSummary() prints the same record.
 *
 * Run:
 *   frida -U -f com.kakao.talk -l frida_feature_trace.js
 *
 * This script observes and logs. It does not modify requests, responses,
 * certificate validation, authentication, or application state.
 */

'use strict';

const CONFIG = {
  schemaVersion: 'security-observation/v1',

  // Safe default for logs that may be sent to an external LLM. Enable raw
  // payloads only for a narrowly scoped, local, authorized follow-up run.
  rawPayload: false,
  includeStack: true,
  stackFrames: 14,
  actionWindowMs: 8000,
  maxBodyKeys: 64,
  maxValueLength: 160,

  commonEvidence: {
    enabled: true,
    maxItemsPerSection: 128,
    maxStateChangeItems: 64,
    maxEvidenceRefsPerItem: 8,
    // Startup produces hundreds of generic observable mutations. In common
    // mode retain state evidence only while a recent user action exists.
    // Set false for a focused startup/background-state investigation.
    onlyActionLinkedState: true,
    // Activity/Fragment lifecycle is already captured by dedicated hooks.
    ignoredStateValueTypes: ['androidx.lifecycle.i$b'],
    // Keep only non-payload result flags in LOCO bodies. ID-shaped keys are
    // still emitted as stable masks for correlation.
    safeLocoValueKeys: ['status', 'isOK', 'success'],
    // Avoid jar:file:/... and other URLStreamHandler noise. OkHttp and HUC
    // network traffic still remains visible.
    networkSchemesOnly: true
  },

  modules: {
    ui: true,
    lifecycle: true,
    observableState: true,
    loco: true,
    okhttp: true,
    webSocket: true,
    httpUrlConnection: true,
    fcm: true,
    protobuf: false
  },

  filters: {
    // Empty means every LOCO method. Example: ['WRITE', 'MSG', 'GETMSGS']
    locoMethods: [],
    // When rawPayload is false, exact LOCO body keys that may still be printed
    // during an authorized focused test. Example: ['msg']. When rawPayload is
    // true all LOCO values are already printed.
    rawLocoKeys: [],
    // Empty means every HTTP host. Example: ['kakao.com', 'kakaocdn.net']
    httpHostContains: []
  },

  appStackPrefixes: [
    'com.kakao',
    'com.quram'
  ]
};

let tracerStarted = false;
let bootstrapAttempts = 0;
let commonSummaryProvider = null;
let commonSummaryPrinter = null;
let commonSummaryResetter = null;
let externalActionMarker = null;

function rpcGetCommonSummary() {
  if (commonSummaryProvider === null) {
    return { status: 'NOT_READY', reason: 'tracer has not initialized' };
  }
  return commonSummaryProvider();
}

function rpcEmitCommonSummary() {
  if (commonSummaryPrinter === null) {
    return { status: 'NOT_READY', reason: 'tracer has not initialized' };
  }
  return commonSummaryPrinter();
}

function rpcResetCommonSummary(label) {
  if (commonSummaryResetter === null) {
    return { status: 'NOT_READY', reason: 'tracer has not initialized' };
  }
  return commonSummaryResetter(label);
}

function rpcMarkUserAction(kind, target) {
  if (externalActionMarker === null) {
    return { status: 'NOT_READY', reason: 'tracer has not initialized' };
  }
  return externalActionMarker(kind, target);
}

rpc.exports = {
  // Frida's Python binding converts snake_case attributes to camelCase.
  // Keep both spellings so typed MCP clients may also call the exact names.
  getCommonSummary: rpcGetCommonSummary,
  get_common_summary: rpcGetCommonSummary,
  emitCommonSummary: rpcEmitCommonSummary,
  emit_common_summary: rpcEmitCommonSummary,
  resetCommonSummary: rpcResetCommonSummary,
  reset_common_summary: rpcResetCommonSummary,
  markUserAction: rpcMarkUserAction,
  mark_user_action: rpcMarkUserAction
};

globalThis.getCommonSummary = function () {
  return commonSummaryProvider === null
    ? { status: 'NOT_READY', reason: 'tracer has not initialized' }
    : commonSummaryProvider();
};

globalThis.printCommonSummary = function () {
  return commonSummaryPrinter === null
    ? { status: 'NOT_READY', reason: 'tracer has not initialized' }
    : commonSummaryPrinter();
};

globalThis.resetCommonSummary = function (label) {
  return commonSummaryResetter === null
    ? { status: 'NOT_READY', reason: 'tracer has not initialized' }
    : commonSummaryResetter(label);
};

function startTracer() {
  Java.perform(function () {
    if (tracerStarted) return;

    bootstrapAttempts += 1;
    let application = null;
    let packageName = null;
    try {
      const ActivityThread = Java.use('android.app.ActivityThread');
      application = ActivityThread.currentApplication();
      if (application !== null) {
        packageName = application.getApplicationContext().getPackageName().toString();
      }
    } catch (_) {}

    if (application === null || packageName !== 'com.kakao.talk') {
      if (bootstrapAttempts === 1 || bootstrapAttempts % 20 === 0) {
        console.log('[TRACE] ' + JSON.stringify({
          stage: 'BOOTSTRAP_WAIT',
          attempt: bootstrapAttempts,
          packageName: packageName
        }));
      }
      setTimeout(startTracer, 250);
      return;
    }

    Java.classFactory.loader = application.getClassLoader();
    // Java.registerClass() writes a temporary dex file. After replacing the
    // default WebView loader, point Frida at the target application's writable
    // code-cache directory as well.
    Java.classFactory.cacheDir = application.getCodeCacheDir().getAbsolutePath().toString();
    tracerStarted = true;
    console.log('[TRACE] ' + JSON.stringify({
      stage: 'CLASS_LOADER_SELECTED',
      packageName: packageName,
      loader: String(application.getClassLoader()),
      cacheDir: Java.classFactory.cacheDir
    }));

    const System = Java.use('java.lang.System');
    const Thread = Java.use('java.lang.Thread');
    const Throwable = Java.use('java.lang.Throwable');
    const Log = Java.use('android.util.Log');
    const JString = Java.use('java.lang.String');
    const Continuation = Java.use('kotlin.coroutines.Continuation');

    const startedAt = Date.now();
    const runId = 'run-' + String(startedAt);
    let sequence = 0;
    let evidenceSequence = 0;
    let lastAction = null;
    let currentActivity = null;
    let currentFragment = null;
    const pendingLoco = Object.create(null);
    const httpCalls = Object.create(null);
    const webSockets = Object.create(null);
    const webSocketTraceRoutes = Object.create(null);
    const urlConnections = Object.create(null);
    const activeUrlResponses = Object.create(null);
    const activeFcmMessages = Object.create(null);
    // A script reload leaves Java.registerClass() output in the process. A
    // unique suffix prevents a second load from colliding with the old bridge.
    const bridgeSuffix = String(startedAt) + '_' + String(bootstrapAttempts);

    let summarySegmentSequence = 0;

    function createCommonSummary(scenarioLabel, previousCollection) {
      summarySegmentSequence += 1;
      const collection = previousCollection
        ? JSON.parse(JSON.stringify(previousCollection))
        : { hooks: {}, gaps: [], truncatedSections: {} };
      collection.truncatedSections = {};
      return {
        schemaVersion: CONFIG.schemaVersion,
        runId: runId,
        segmentId: runId + '-segment-' + String(summarySegmentSequence),
        scenarioLabel: scenarioLabel || null,
        source: 'frida_feature_trace.js',
        packageName: packageName,
        startedAtEpochMs: startedAt,
        segmentStartedAtElapsedMs: now() - startedAt,
        updatedAtElapsedMs: 0,
        eventCount: 0,
        privacy: {
          rawPayload: CONFIG.rawPayload,
          summaryContainsPayloadValues: false
        },
        fieldCoverage: {
          actors: 'INFERENCE_REQUIRED',
          entry_points: 'OBSERVED_PARTIAL',
          preconditions: 'TARGETED_TEST_REQUIRED',
          security_assets: 'INFERENCE_REQUIRED',
          controllable_inputs: 'FIELD_NAMES_OBSERVED_CONTROLLABILITY_NOT_PROVEN',
          trust_boundaries: 'INFERENCE_REQUIRED',
          protocol: 'OBSERVED_PARTIAL',
          expected_authorization: 'TARGETED_TEST_REQUIRED',
          state_changes: 'OBSERVED_PARTIAL',
          data_storage: 'NOT_COLLECTED',
          external_destinations: 'OBSERVED_PARTIAL',
          failure_behavior: 'ONLY_WHEN_TRIGGERED',
          security_unknowns: 'ANALYST_OR_LLM_REQUIRED',
          evidence_refs: 'COLLECTED'
        },
        collection: collection,
        commonInformation: {
          entry_points: [],
          screens: [],
          observed_input_fields: [],
          protocols: {
            loco: [],
            http: [],
            websocket: [],
            push: []
          },
          state_changes: [],
          external_destinations: [],
          failure_behavior: []
        },
        limitations: [
          'Observed request fields are not automatically proven user-controllable.',
          'A successful request does not prove the server authorization rule.',
          'Temporal action linkage is context, not proof of causality.',
          'Database, file, SharedPreferences, and Keystore persistence are not collected.',
          'Native sockets outside the installed Java/OkHttp/LOCO hooks may be absent.'
        ]
      };
    }

    let commonSummary = createCommonSummary(null, null);

    function now() {
      return Date.now();
    }

    function elapsed() {
      return '+' + (now() - startedAt) + 'ms';
    }

    function nextId(prefix) {
      sequence += 1;
      return prefix + '-' + sequence;
    }

    function nextEvidenceRef() {
      evidenceSequence += 1;
      return 'evidence-' + evidenceSequence;
    }

    function cloneCommonSummary() {
      commonSummary.updatedAtElapsedMs = now() - startedAt;
      return JSON.parse(JSON.stringify(commonSummary));
    }

    function appendUnique(list, value) {
      if (value === null || value === undefined || value === '') return;
      if (list.indexOf(value) === -1) list.push(value);
    }

    function addEvidenceRef(item, evidenceRef) {
      if (!item || !evidenceRef) return;
      if (!item.evidence_refs) item.evidence_refs = [];
      if (item.evidence_refs.indexOf(evidenceRef) !== -1) return;
      if (item.evidence_refs.length < CONFIG.commonEvidence.maxEvidenceRefsPerItem) {
        item.evidence_refs.push(evidenceRef);
      }
    }

    function getOrAdd(sectionName, list, key, seed) {
      for (let i = 0; i < list.length; i += 1) {
        if (list[i].key === key) return list[i];
      }
      const sectionLimit = sectionName === 'state_changes'
        ? CONFIG.commonEvidence.maxStateChangeItems
        : CONFIG.commonEvidence.maxItemsPerSection;
      if (list.length >= sectionLimit) {
        commonSummary.collection.truncatedSections[sectionName] =
          (commonSummary.collection.truncatedSections[sectionName] || 0) + 1;
        return null;
      }
      const item = Object.assign({ key: key, evidence_refs: [] }, seed || {});
      list.push(item);
      return item;
    }

    function normalizedNetworkRoute(urlValue, fallbackHost) {
      const text = (urlValue === null || urlValue === undefined ? '' : String(urlValue))
        .replace(/<id#[^>]+>/g, ':id');
      const match = /^([a-z][a-z0-9+.-]*):\/\/([^\/?#:]+)([^?#]*)/i.exec(text);
      const scheme = match ? match[1].toLowerCase() : null;
      const host = match ? match[2] : (fallbackHost || null);
      const rawPath = match ? (match[3] || '/') : '/';
      const route = rawPath.split('/').map(function (segment) {
        if (!segment) return segment;
        if (/^\d+$/.test(segment) || /^[0-9a-f-]{16,}$/i.test(segment) || segment.length > 40) {
          return ':id';
        }
        return segment;
      }).join('/') || '/';
      return { scheme: scheme, host: host, route: route };
    }

    function queryKeyNames(urlValue) {
      const text = urlValue === null || urlValue === undefined ? '' : String(urlValue);
      const question = text.indexOf('?');
      if (question === -1) return [];
      const query = text.slice(question + 1).split('#')[0];
      return query.split('&').filter(Boolean).map(function (pair) {
        const rawKey = pair.split('=')[0];
        try { return decodeURIComponent(rawKey); } catch (_) { return rawKey; }
      }).filter(Boolean).sort();
    }

    function packetBodyKeys(packet) {
      if (!packet || !packet.body || !Array.isArray(packet.body.keys)) return [];
      return packet.body.keys.slice().sort();
    }

    function headerNames(request) {
      if (!request || !request.headers || !Array.isArray(request.headers.names)) return [];
      return request.headers.names.slice().sort();
    }

    function producerFrame(stack) {
      if (!Array.isArray(stack)) return null;
      for (let i = 0; i < stack.length; i += 1) {
        const line = String(stack[i]);
        if (line.indexOf('Native Method') !== -1) continue;
        if (line.indexOf('.r0a1.') !== -1 || line.indexOf('.we80.') !== -1) continue;
        return line;
      }
      return stack.length ? String(stack[0]) : null;
    }

    function shouldTraceObservableState(value, stack) {
      if (!hasAppFrame(stack)) return false;
      if (CONFIG.commonEvidence.onlyActionLinkedState && recentAction() === null) {
        return false;
      }
      return CONFIG.commonEvidence.ignoredStateValueTypes.indexOf(className(value)) === -1;
    }

    function stageDescriptor(stage) {
      if (stage === 'USER_ACTION') {
        return { category: 'ENTRY_POINT', mapsTo: ['entry_points', 'evidence_refs'] };
      }
      if (/^(?:ACTIVITY|FRAGMENT)_/.test(stage)) {
        return { category: 'SCREEN_CONTEXT', mapsTo: ['entry_points', 'state_changes', 'evidence_refs'] };
      }
      if (/^(?:STATEFLOW|LIVEDATA)_/.test(stage)) {
        return { category: 'STATE_CHANGE', mapsTo: ['state_changes', 'evidence_refs'] };
      }
      if (/^LOCO_/.test(stage)) {
        return { category: 'PROTOCOL', mapsTo: ['controllable_inputs', 'protocol', 'failure_behavior', 'evidence_refs'] };
      }
      if (/^(?:HTTP|URL_CONNECTION)_/.test(stage)) {
        return { category: 'NETWORK', mapsTo: ['controllable_inputs', 'protocol', 'external_destinations', 'failure_behavior', 'evidence_refs'] };
      }
      if (/^WEBSOCKET_/.test(stage)) {
        return { category: 'PROTOCOL', mapsTo: ['protocol', 'external_destinations', 'failure_behavior', 'evidence_refs'] };
      }
      if (/^FCM_/.test(stage)) {
        return { category: 'PUSH', mapsTo: ['protocol', 'external_destinations', 'failure_behavior', 'evidence_refs'] };
      }
      if (stage === 'HOOK_OK' || stage === 'HOOK_FAIL' || stage === 'READY') {
        return { category: 'COLLECTION_STATUS', mapsTo: ['evidence_refs'] };
      }
      return { category: 'RUNTIME', mapsTo: ['evidence_refs'] };
    }

    function currentContext(action) {
      return {
        activity: currentActivity,
        fragment: currentFragment,
        actionRef: action && action.id ? action.id : null,
        actionLink: action && action.id ? 'TEMPORAL_WINDOW' : null
      };
    }

    function addObservedInput(source, operation, field, evidenceRef) {
      const list = commonSummary.commonInformation.observed_input_fields;
      const item = getOrAdd(
        'observed_input_fields',
        list,
        source + '|' + operation + '|' + field,
        {
          source: source,
          operation: operation,
          field: field,
          status: 'OBSERVED_FIELD_NOT_PROVEN_CONTROLLABLE'
        }
      );
      addEvidenceRef(item, evidenceRef);
    }

    function addExternalDestination(transport, host, evidenceRef) {
      if (!host) return;
      const list = commonSummary.commonInformation.external_destinations;
      const item = getOrAdd(
        'external_destinations',
        list,
        transport + '|' + host,
        { transport: transport, host: host, status: 'OBSERVED' }
      );
      addEvidenceRef(item, evidenceRef);
    }

    function collectCommon(stage, record) {
      if (!CONFIG.commonEvidence.enabled) return;
      commonSummary.eventCount += 1;

      if (stage === 'HOOK_OK' || stage === 'HOOK_FAIL') {
        commonSummary.collection.hooks[record.hook || 'unknown'] = {
          status: stage === 'HOOK_OK' ? 'INSTALLED' : 'FAILED',
          evidence_ref: record.evidenceRef,
          error: stage === 'HOOK_FAIL' ? String(record.error || 'unknown') : null
        };
        if (stage === 'HOOK_FAIL') {
          const gap = getOrAdd(
            'collection.gaps',
            commonSummary.collection.gaps,
            String(record.hook || 'unknown'),
            { hook: record.hook || 'unknown', reason: 'HOOK_FAILED' }
          );
          addEvidenceRef(gap, record.evidenceRef);
        }
        return;
      }

      if (stage === 'USER_ACTION') {
        const entry = getOrAdd(
          'entry_points',
          commonSummary.commonInformation.entry_points,
          String(record.kind) + '|' + String(record.target),
          {
            kind: record.kind,
            target: record.target,
            status: 'OBSERVED',
            activity: record.common.context.activity,
            fragment: record.common.context.fragment
          }
        );
        addEvidenceRef(entry, record.evidenceRef);
      }

      if (/^(?:ACTIVITY|FRAGMENT)_/.test(stage)) {
        const screen = getOrAdd(
          'screens',
          commonSummary.commonInformation.screens,
          stage + '|' + String(record.component),
          { event: stage, component: record.component, status: 'OBSERVED' }
        );
        addEvidenceRef(screen, record.evidenceRef);
      }

      if (/^(?:STATEFLOW|LIVEDATA)_/.test(stage)) {
        const valueType = record.value && record.value.type ? record.value.type : 'unknown';
        const producer = producerFrame(record.stack);
        const state = getOrAdd(
          'state_changes',
          commonSummary.commonInformation.state_changes,
          stage + '|' + valueType + '|' + String(producer),
          {
            mutation: stage,
            valueType: valueType,
            producer: producer,
            status: 'OBSERVED_VALUE_TYPE_ONLY'
          }
        );
        addEvidenceRef(state, record.evidenceRef);
      }

      if (/^LOCO_/.test(stage) && stage !== 'LOCO_SUSPENDED') {
        const method = String(record.method ||
          (record.packet && record.packet.header && record.packet.header.method) || 'unknown');
        const protocols = commonSummary.commonInformation.protocols.loco;
        const protocol = getOrAdd(
          'protocols.loco',
          protocols,
          method,
          {
            method: method,
            directions: [],
            requestFields: [],
            responseFields: [],
            pushFields: [],
            correlationFields: ['trace', 'packetId'],
            status: 'OBSERVED_PARTIAL'
          }
        );
        const keys = packetBodyKeys(record.packet);
        if (protocol) {
          if (stage === 'LOCO_REQUEST') {
            appendUnique(protocol.directions, 'request');
            keys.forEach(function (key) {
              appendUnique(protocol.requestFields, key);
              addObservedInput('LOCO', method, key, record.evidenceRef);
            });
          } else if (stage === 'LOCO_PUSH_INGRESS') {
            appendUnique(protocol.directions, 'push');
            keys.forEach(function (key) { appendUnique(protocol.pushFields, key); });
          } else if (/RESPONSE/.test(stage)) {
            appendUnique(protocol.directions, 'response');
            keys.forEach(function (key) { appendUnique(protocol.responseFields, key); });
          } else if (/FAILURE/.test(stage)) {
            appendUnique(protocol.directions, 'failure');
          }
          addEvidenceRef(protocol, record.evidenceRef);
        }
      }

      if (/^HTTP_/.test(stage)) {
        const request = record.request || {};
        const method = String(request.method || 'unknown');
        const route = String(request.route || normalizedNetworkRoute(request.url, request.host).route);
        const host = request.host || normalizedNetworkRoute(request.url, null).host;
        if (host) {
          const endpoint = getOrAdd(
            'protocols.http',
            commonSummary.commonInformation.protocols.http,
            method + '|' + host + '|' + route,
            {
              method: method,
              host: host,
              route: route,
              eventTypes: [],
              queryFields: [],
              authenticationIndicatorHeaders: [],
              responseCodes: [],
              status: 'OBSERVED_PARTIAL'
            }
          );
          if (endpoint) {
            appendUnique(endpoint.eventTypes, stage);
            (request.queryKeys || []).forEach(function (key) {
              appendUnique(endpoint.queryFields, key);
              addObservedInput('HTTP_QUERY', method + ' ' + host + route, key, record.evidenceRef);
            });
            headerNames(request).forEach(function (name) {
              if (/(?:authorization|cookie|token|signature|csrf|api[-_]?key)/i.test(name)) {
                appendUnique(endpoint.authenticationIndicatorHeaders, name);
              }
            });
            if (record.response && record.response.code !== null && record.response.code !== undefined) {
              appendUnique(endpoint.responseCodes, Number(record.response.code));
            }
            addEvidenceRef(endpoint, record.evidenceRef);
          }
          addExternalDestination('HTTP', host, record.evidenceRef);
        }
      }

      if (/^URL_CONNECTION_/.test(stage)) {
        const routeInfo = normalizedNetworkRoute(record.url, null);
        if (routeInfo.host && (routeInfo.scheme === 'http' || routeInfo.scheme === 'https')) {
          if (stage !== 'URL_CONNECTION_OPEN') {
            const method = String(record.method || 'unknown');
            const route = record.route || routeInfo.route;
            const endpoint = getOrAdd(
              'protocols.http',
              commonSummary.commonInformation.protocols.http,
              method + '|' + routeInfo.host + '|' + route,
              {
                method: method,
                host: routeInfo.host,
                route: route,
                eventTypes: [],
                queryFields: [],
                authenticationIndicatorHeaders: [],
                responseCodes: [],
                status: 'OBSERVED_PARTIAL'
              }
            );
            if (endpoint) {
              appendUnique(endpoint.eventTypes, stage);
              (record.queryKeys || []).forEach(function (key) {
                appendUnique(endpoint.queryFields, key);
                addObservedInput(
                  'HTTP_URL_CONNECTION_QUERY',
                  method + ' ' + routeInfo.host + route,
                  key,
                  record.evidenceRef
                );
              });
              const names = record.headers && Array.isArray(record.headers.names)
                ? record.headers.names : [];
              names.forEach(function (name) {
                if (/(?:authorization|cookie|token|signature|csrf|api[-_]?key)/i.test(name)) {
                  appendUnique(endpoint.authenticationIndicatorHeaders, name);
                }
              });
              if (record.code !== null && record.code !== undefined) {
                appendUnique(endpoint.responseCodes, Number(record.code));
              }
              addEvidenceRef(endpoint, record.evidenceRef);
            }
          }
          addExternalDestination('HTTP_URL_CONNECTION', routeInfo.host, record.evidenceRef);
        }
      }

      if (/^WEBSOCKET_/.test(stage)) {
        const request = record.request || {};
        const requestHost = request.host || null;
        const requestRoute = request.route || normalizedNetworkRoute(request.url, requestHost).route;
        if (requestHost) {
          webSocketTraceRoutes[record.trace] = { host: requestHost, route: requestRoute };
        }
        const knownRoute = webSocketTraceRoutes[record.trace] || {};
        const host = requestHost || knownRoute.host || null;
        const route = requestHost ? requestRoute : (knownRoute.route || null);
        if (host) {
          const endpoint = getOrAdd(
            'protocols.websocket',
            commonSummary.commonInformation.protocols.websocket,
            String(host) + '|' + String(route),
            { host: host, route: route, eventTypes: [], status: 'OBSERVED_PARTIAL' }
          );
          if (endpoint) {
            appendUnique(endpoint.eventTypes, stage);
            addEvidenceRef(endpoint, record.evidenceRef);
          }
          addExternalDestination('WEBSOCKET', host, record.evidenceRef);
        }
      }

      if (/^FCM_/.test(stage)) {
        const push = getOrAdd(
          'protocols.push',
          commonSummary.commonInformation.protocols.push,
          'FCM',
          { transport: 'FCM', eventTypes: [], dataFields: [], status: 'OBSERVED_PARTIAL' }
        );
        if (push) {
          appendUnique(push.eventTypes, stage);
          (record.dataKeys || []).forEach(function (key) { appendUnique(push.dataFields, key); });
          addEvidenceRef(push, record.evidenceRef);
        }
      }

      if (stage !== 'HOOK_FAIL' && (stage.indexOf('FAILURE') !== -1 || stage === 'TRACE_ERROR')) {
        const failure = getOrAdd(
          'failure_behavior',
          commonSummary.commonInformation.failure_behavior,
          stage + '|' + String(record.method || record.where ||
            (record.request && record.request.host) || 'unknown'),
          {
            event: stage,
            operation: record.method || record.where || null,
            target: record.request && record.request.host ? record.request.host : null,
            status: 'OBSERVED_FAILURE_PATH'
          }
        );
        addEvidenceRef(failure, record.evidenceRef);
      }
    }

    function identity(value) {
      try {
        return String(System.identityHashCode(value));
      } catch (_) {
        return 'unknown';
      }
    }

    function className(value) {
      if (value === null || value === undefined) return 'null';
      try {
        return value.getClass().getName().toString();
      } catch (_) {
        try {
          return value.$className || typeof value;
        } catch (_) {
          return 'unknown';
        }
      }
    }

    function safeString(value) {
      if (value === null || value === undefined) return 'null';
      try {
        return String(value.toString());
      } catch (e) {
        return '<toString failed: ' + e + '>';
      }
    }

    function stableMask(value) {
      const text = String(value);
      let hash = 2166136261;
      for (let i = 0; i < text.length; i += 1) {
        hash ^= text.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
      }
      return '<id#' + (hash >>> 0).toString(16) + '>';
    }

    function isSensitiveKey(key) {
      return /(?:token|auth|cookie|session|password|secret|credential|api[-_]?key|signature|jwt|bearer|csrf|msg|message|chatlog|payload|body|data|value|text|content|title|description|name|url|uri|path|supplement|extra|attachment|photo|video|audio|file|contact|nickname|email|phone|from)/i.test(key);
    }

    function formatValue(key, value) {
      if (value === null || value === undefined) return null;
      const text = safeString(value);
      if (CONFIG.rawPayload) return text;
      if (/(?:id|uuid)$/i.test(String(key))) {
        return stableMask(text);
      }
      if (isSensitiveKey(key)) return '<redacted len=' + text.length + '>';
      if (text.length > CONFIG.maxValueLength) {
        return '<' + className(value) + ' len=' + text.length + '>';
      }
      return text;
    }

    function formatHeaderValue(name, value) {
      if (value === null || value === undefined) return null;
      const text = safeString(value);
      if (CONFIG.rawPayload) return text;
      // Unknown/custom headers frequently carry device or account identifiers.
      // Retain only transport metadata values in the default redacted mode.
      if (/^(?:accept|accept-encoding|accept-language|cache-control|connection|content-length|content-type|date|host|talk-agent|talk-language|user-agent)$/i.test(String(name))) {
        return text.length > CONFIG.maxValueLength
          ? '<redacted len=' + text.length + '>'
          : text;
      }
      if (isSensitiveKey(name)) return '<redacted len=' + text.length + '>';
      return '<redacted len=' + text.length + '>';
    }

    function formatLocoBodyValue(key, value) {
      if (value === null || value === undefined) return null;
      const text = safeString(value);
      if (CONFIG.rawPayload || CONFIG.filters.rawLocoKeys.indexOf(key) !== -1) {
        return text.slice(0, CONFIG.maxValueLength);
      }
      if (/(?:id|uuid)$/i.test(String(key))) return stableMask(text);
      if (CONFIG.commonEvidence.safeLocoValueKeys.indexOf(String(key)) !== -1) {
        return text.length > CONFIG.maxValueLength
          ? '<redacted len=' + text.length + '>'
          : text;
      }
      return '<redacted len=' + text.length + '>';
    }

    function emit(stage, traceId, detail) {
      const evidenceRef = nextEvidenceRef();
      const descriptor = stageDescriptor(stage);
      const action = stage === 'USER_ACTION'
        ? { id: traceId, kind: detail && detail.kind, target: detail && detail.target }
        : (detail && detail.action !== undefined ? detail.action : recentAction());
      const record = Object.assign({
        schemaVersion: CONFIG.schemaVersion,
        runId: runId,
        evidenceRef: evidenceRef,
        observationStatus: 'OBSERVED',
        t: elapsed(),
        thread: Thread.currentThread().getName().toString(),
        stage: stage,
        trace: traceId || '-'
      }, detail || {});
      record.common = {
        category: descriptor.category,
        mapsTo: descriptor.mapsTo,
        context: currentContext(action)
      };
      collectCommon(stage, record);
      console.log('[TRACE] ' + JSON.stringify(record));
    }

    commonSummaryProvider = function () {
      return cloneCommonSummary();
    };

    commonSummaryPrinter = function () {
      const snapshot = cloneCommonSummary();
      console.log('[COMMON] ' + JSON.stringify(snapshot));
      return snapshot;
    };

    commonSummaryResetter = function (label) {
      commonSummary = createCommonSummary(
        label === null || label === undefined ? null : String(label),
        commonSummary.collection
      );
      lastAction = null;
      return cloneCommonSummary();
    };

    function fullStack() {
      if (!CONFIG.includeStack) return [];
      try {
        return Log.getStackTraceString(Throwable.$new())
          .toString()
          .split('\n')
          .map(function (line) { return line.trim(); });
      } catch (_) {
        return [];
      }
    }

    function appStack() {
      const lines = fullStack();
      return lines.filter(function (line) {
        return CONFIG.appStackPrefixes.some(function (prefix) {
          return line.indexOf(prefix) !== -1;
        });
      }).slice(0, CONFIG.stackFrames);
    }

    function hasAppFrame(lines) {
      return lines.some(function (line) {
        return CONFIG.appStackPrefixes.some(function (prefix) {
          return line.indexOf(prefix) !== -1;
        });
      });
    }

    function recentAction() {
      if (lastAction === null || now() - lastAction.at > CONFIG.actionWindowMs) {
        return null;
      }
      return {
        id: lastAction.id,
        kind: lastAction.kind,
        target: lastAction.target
      };
    }

    function markAction(kind, target, detail) {
      const actionId = nextId('action');
      lastAction = { id: actionId, kind: kind, target: target, at: now() };
      emit('USER_ACTION', actionId, Object.assign({
        kind: kind,
        target: target,
        stack: appStack()
      }, detail || {}));
      return recentAction();
    }

    externalActionMarker = function (kind, target) {
      let result = null;
      Java.performNow(function () {
        result = markAction(String(kind || 'automation'), String(target || 'unknown'), {
          source: 'HOST_AUTOMATION'
        });
      });
      return result;
    };

    function getDeclaredFieldValue(value, ownerName, candidates) {
      if (value === null || value === undefined) return null;
      try {
        const klass = Java.use(ownerName).class;
        for (let i = 0; i < candidates.length; i += 1) {
          try {
            const field = klass.getDeclaredField(candidates[i]);
            field.setAccessible(true);
            return field.get(value);
          } catch (_) {}
        }
      } catch (_) {}
      return null;
    }

    function callNoArg(value, candidates) {
      if (value === null || value === undefined) return null;
      for (let i = 0; i < candidates.length; i += 1) {
        try {
          const fn = value[candidates[i]];
          if (fn) return fn.call(value);
        } catch (_) {}
      }
      return null;
    }

    function valueSummary(value) {
      if (value === null || value === undefined) return { type: 'null' };
      const text = safeString(value);
      return {
        type: className(value),
        value: CONFIG.rawPayload
          ? text
          : '<redacted len=' + text.length + '>'
      };
    }

    function install(name, installer) {
      try {
        installer();
        emit('HOOK_OK', '-', { hook: name });
      } catch (e) {
        emit('HOOK_FAIL', '-', { hook: name, error: String(e) });
      }
    }

    function isAllowedLocoMethod(method) {
      const filters = CONFIG.filters.locoMethods;
      return filters.length === 0 || filters.indexOf(method) !== -1;
    }

    function hostAllowed(host) {
      const filters = CONFIG.filters.httpHostContains;
      if (filters.length === 0) return true;
      return filters.some(function (needle) {
        return String(host).indexOf(needle) !== -1;
      });
    }

    function viewName(view) {
      try {
        const id = view.getId();
        if (id === -1) return className(view) + '#NO_ID';
        return view.getResources().getResourceName(id).toString();
      } catch (_) {
        return className(view);
      }
    }

    function installUiHooks() {
      install('android.view.View.performClick', function () {
        const View = Java.use('android.view.View');
        const original = View.performClick.overload();
        original.implementation = function () {
          markAction('click', viewName(this));
          return original.call(this);
        };
      });

      install('android.view.View.performLongClick', function () {
        const View = Java.use('android.view.View');
        const original = View.performLongClick.overload();
        original.implementation = function () {
          markAction('long_click', viewName(this));
          return original.call(this);
        };
      });

      install('android.widget.TextView.onEditorAction', function () {
        const TextView = Java.use('android.widget.TextView');
        const original = TextView.onEditorAction.overload('int');
        original.implementation = function (actionCode) {
          markAction('editor_action', viewName(this), { actionCode: actionCode });
          return original.call(this, actionCode);
        };
      });
    }

    function installLifecycleHooks() {
      install('android.app.Activity lifecycle', function () {
        const Activity = Java.use('android.app.Activity');
        [
          ['onCreate', ['android.os.Bundle'], 'ACTIVITY_CREATE'],
          ['onResume', [], 'ACTIVITY_RESUME'],
          ['onPause', [], 'ACTIVITY_PAUSE'],
          ['onDestroy', [], 'ACTIVITY_DESTROY']
        ].forEach(function (spec) {
          const original = Activity[spec[0]].overload.apply(Activity[spec[0]], spec[1]);
          original.implementation = function () {
            const name = className(this);
            if (name.indexOf('com.kakao') === 0) {
              if (spec[2] === 'ACTIVITY_CREATE' || spec[2] === 'ACTIVITY_RESUME') {
                currentActivity = name;
              }
              emit(spec[2], '-', { component: name, action: recentAction() });
            }
            const result = original.apply(this, arguments);
            if (spec[2] === 'ACTIVITY_DESTROY' && currentActivity === name) {
              currentActivity = null;
            }
            return result;
          };
        });
      });

      install('androidx.fragment.app.Fragment lifecycle', function () {
        const Fragment = Java.use('androidx.fragment.app.Fragment');
        [
          ['onResume', 'FRAGMENT_RESUME'],
          ['onPause', 'FRAGMENT_PAUSE']
        ].forEach(function (spec) {
          const original = Fragment[spec[0]].overload();
          original.implementation = function () {
            const name = className(this);
            if (name.indexOf('com.kakao') === 0) {
              if (spec[1] === 'FRAGMENT_RESUME') currentFragment = name;
              emit(spec[1], '-', { component: name, action: recentAction() });
            }
            const result = original.call(this);
            if (spec[1] === 'FRAGMENT_PAUSE' && currentFragment === name) {
              currentFragment = null;
            }
            return result;
          };
        });
      });
    }

    function installObservableStateHooks() {
      install('AndroidX LiveData state', function () {
        // R8 name in the inspected 26.7.1 build. q.n = postValue, q.q = setValue.
        const LiveData = Java.use('androidx.lifecycle.q');
        [
          ['n', 'LIVEDATA_POST'],
          ['q', 'LIVEDATA_SET']
        ].forEach(function (spec) {
          const original = LiveData[spec[0]].overload('java.lang.Object');
          original.implementation = function (value) {
            if (CONFIG.commonEvidence.onlyActionLinkedState && recentAction() === null) {
              return original.call(this, value);
            }
            const lines = fullStack();
            if (shouldTraceObservableState(value, lines)) {
              emit(spec[1], nextId('state'), {
                ownerClass: className(this),
                value: valueSummary(value),
                action: recentAction(),
                stack: lines.filter(function (line) {
                  return CONFIG.appStackPrefixes.some(function (prefix) {
                    return line.indexOf(prefix) !== -1;
                  });
                }).slice(0, CONFIG.stackFrames)
              });
            }
            return original.call(this, value);
          };
        });
      });

      install('Kotlin StateFlow public mutation', function () {
        // r0a1.q(expectedState, newState) is StateFlowImpl's synchronized
        // internal mutation loop. Hooking that very hot internal method can
        // crash ART on Android 14. Observe the public mutation entry points
        // instead; emit()/tryEmit() delegate to setValue(), while atomic
        // update loops use compareAndSet().
        const StateFlow = Java.use('com.quram.mi.ocr.r0a1');

        const setValue = StateFlow.setValue.overload('java.lang.Object');
        setValue.implementation = function (newState) {
          if (CONFIG.commonEvidence.onlyActionLinkedState && recentAction() === null) {
            return setValue.call(this, newState);
          }
          const lines = fullStack();
          const shouldTrace = shouldTraceObservableState(newState, lines);
          const result = setValue.call(this, newState);
          if (shouldTrace) {
            emit('STATEFLOW_SET', nextId('state'), {
              ownerClass: className(this),
              value: valueSummary(newState),
              action: recentAction(),
              stack: lines.filter(function (line) {
                return CONFIG.appStackPrefixes.some(function (prefix) {
                  return line.indexOf(prefix) !== -1;
                });
              }).slice(0, CONFIG.stackFrames)
            });
          }
          return result;
        };

        const compareAndSet = StateFlow.compareAndSet.overload(
          'java.lang.Object',
          'java.lang.Object'
        );
        compareAndSet.implementation = function (expectedState, newState) {
          if (CONFIG.commonEvidence.onlyActionLinkedState && recentAction() === null) {
            return compareAndSet.call(this, expectedState, newState);
          }
          const lines = fullStack();
          const shouldTrace = shouldTraceObservableState(newState, lines);
          const changed = compareAndSet.call(this, expectedState, newState);
          if (shouldTrace && changed) {
            emit('STATEFLOW_COMPARE_AND_SET', nextId('state'), {
              ownerClass: className(this),
              value: valueSummary(newState),
              action: recentAction(),
              stack: lines.filter(function (line) {
                return CONFIG.appStackPrefixes.some(function (prefix) {
                  return line.indexOf(prefix) !== -1;
                });
              }).slice(0, CONFIG.stackFrames)
            });
          }
          return changed;
        };
      });
    }

    function packetParts(packet) {
      return {
        header: getDeclaredFieldValue(packet, 'com.quram.mi.ocr.nl30', ['a', 'header']),
        body: getDeclaredFieldValue(packet, 'com.quram.mi.ocr.nl30', ['b', 'body'])
      };
    }

    function headerParts(header) {
      if (header === null) return {};
      const methodObject = getDeclaredFieldValue(header, 'com.quram.mi.ocr.fi30', ['c', 'method']);
      return {
        packetId: formatValue('packetId', getDeclaredFieldValue(header, 'com.quram.mi.ocr.fi30', ['a', 'packetId'])),
        status: formatValue('status', getDeclaredFieldValue(header, 'com.quram.mi.ocr.fi30', ['b', 'status'])),
        method: safeString(methodObject),
        isPush: safeString(callNoArg(methodObject, ['getIsPush', 'isPush'])),
        bodyLength: formatValue('bodyLength', getDeclaredFieldValue(header, 'com.quram.mi.ocr.fi30', ['d', 'bodyLength']))
      };
    }

    function bodySummary(body) {
      if (body === null) return { keys: [], values: {} };
      const bson = getDeclaredFieldValue(body, 'com.quram.mi.ocr.xf30', ['a', 'bson']);
      if (bson === null) return { type: className(body) };

      const keys = [];
      const values = {};
      let truncated = false;
      try {
        // Reflection returns the field as java.lang.Object, so Frida only
        // exposes Object methods on that wrapper. Cast it to the BSONObject
        // interface and then to Map before calling keySet()/get().
        const BsonObject = Java.use('com.quram.mi.ocr.t62');
        const JavaMap = Java.use('java.util.Map');
        const bsonObject = Java.cast(bson, BsonObject);
        const map = Java.cast(bsonObject.toMap(), JavaMap);
        const iterator = map.keySet().iterator();
        while (iterator.hasNext()) {
          const key = String(iterator.next());
          if (keys.length >= CONFIG.maxBodyKeys) {
            truncated = true;
            break;
          }
          keys.push(key);
          const value = map.get(JString.$new(key));
          values[key] = formatLocoBodyValue(key, value);
        }
        keys.sort();
        return { keys: keys, values: values, truncated: truncated };
      } catch (e) {
        return { type: className(bson), error: String(e) };
      }
    }

    function packetInfo(packet) {
      const parts = packetParts(packet);
      return {
        packetClass: className(packet),
        header: headerParts(parts.header),
        body: bodySummary(parts.body)
      };
    }

    function isCoroutineSuspended(value) {
      return className(value).indexOf('CoroutineSingletons') !== -1 &&
        safeString(value) === 'COROUTINE_SUSPENDED';
    }

    function coroutineFailure(value) {
      if (className(value) !== 'kotlin.Result$Failure') return null;
      return getDeclaredFieldValue(value, 'kotlin.Result$Failure', ['exception', 'C']);
    }

    function installLocoHooks() {
      const LocoJob = Java.use('com.kakao.talk.core.loco.protocol.job.LocoJob');

      let TraceContinuation = null;
      install('LOCO continuation bridge', function () {
        TraceContinuation = Java.registerClass({
          name: 'com.audit.frida.FeatureTraceContinuation_' + bridgeSuffix,
          implements: [Continuation],
          fields: {
            delegate: 'kotlin.coroutines.Continuation',
            traceId: 'java.lang.String'
          },
          methods: {
            $init: [{
              returnType: 'void',
              argumentTypes: ['kotlin.coroutines.Continuation', 'java.lang.String'],
              implementation: function (delegate, traceId) {
                this.delegate.value = delegate;
                this.traceId.value = traceId;
              }
            }],
            getContext: function () {
              return this.delegate.value.getContext();
            },
            resumeWith: function (result) {
              const traceId = String(this.traceId.value);
              const meta = pendingLoco[traceId];
              if (meta) {
                try {
                  const failure = coroutineFailure(result);
                  if (failure !== null) {
                    emit('LOCO_FAILURE_ASYNC', traceId, {
                      latencyMs: now() - meta.at,
                      method: meta.method,
                      error: safeString(failure)
                    });
                  } else {
                    emit('LOCO_RESPONSE_ASYNC', traceId, {
                      latencyMs: now() - meta.at,
                      method: meta.method,
                      packet: packetInfo(result)
                    });
                  }
                } catch (e) {
                  emit('TRACE_ERROR', traceId, { where: 'LOCO resumeWith', error: String(e) });
                }
                delete pendingLoco[traceId];
              }
              return this.delegate.value.resumeWith(result);
            }
          }
        });
      });

      install('LocoJob.g all request/response', function () {
        const original = LocoJob.g.overload(
          'com.quram.mi.ocr.tl30',
          'kotlin.coroutines.Continuation'
        );
        original.implementation = function (request, continuation) {
          // Kotlin state-machine re-entry calls g(null, continuation).
          if (request === null) return original.call(this, request, continuation);

          const info = packetInfo(request);
          const method = info.header.method;
          if (!isAllowedLocoMethod(method)) {
            return original.call(this, request, continuation);
          }

          const traceId = nextId('loco');
          pendingLoco[traceId] = { at: now(), method: method };
          emit('LOCO_REQUEST', traceId, {
            method: method,
            action: recentAction(),
            jobClass: className(this),
            packet: info,
            stack: appStack()
          });

          const wrapped = TraceContinuation
            ? TraceContinuation.$new(continuation, JString.$new(traceId))
            : continuation;
          let result;
          try {
            result = original.call(this, request, wrapped);
          } catch (e) {
            emit('LOCO_FAILURE', traceId, { method: method, error: String(e) });
            delete pendingLoco[traceId];
            throw e;
          }

          if (isCoroutineSuspended(result)) {
            // A continuation is allowed to resume before the suspend function
            // returns. In that case resumeWith() already emitted and removed
            // the pending entry, so do not emit a misleading late SUSPENDED.
            if (pendingLoco[traceId]) {
              emit('LOCO_SUSPENDED', traceId, {
                method: method,
                packetId: info.header.packetId
              });
            }
          } else {
            const syncMeta = pendingLoco[traceId];
            emit('LOCO_RESPONSE_SYNC', traceId, {
              latencyMs: syncMeta ? now() - syncMeta.at : null,
              method: method,
              packet: packetInfo(result)
            });
            delete pendingLoco[traceId];
          }
          return result;
        };
      });

      install('LOCO push ingress', function () {
        const Dispatcher = Java.use('com.quram.mi.ocr.dkz0');
        const original = Dispatcher.o0.overload(
          'com.quram.mi.ocr.ul30',
          'kotlin.coroutines.Continuation'
        );
        original.implementation = function (response, continuation) {
          const info = packetInfo(response);
          const method = info.header.method;
          if (isAllowedLocoMethod(method)) {
            emit('LOCO_PUSH_INGRESS', nextId('push'), {
              method: method,
              packet: info,
              action: recentAction(),
              stack: appStack()
            });
          }
          return original.call(this, response, continuation);
        };
      });
    }

    function sanitizedUrl(urlValue) {
      const text = safeString(urlValue);
      if (CONFIG.rawPayload) return text;
      const match = /^([a-z][a-z0-9+.-]*:\/\/[^/?#]+)([^?#]*)(?:\?([^#]*))?/i.exec(text);
      if (!match) return '<url#' + stableMask(text).slice(4);
      const path = (match[2] || '').split('/').map(function (segment) {
        if (!segment) return segment;
        if (/^\d+$/.test(segment) || /^[0-9a-f-]{16,}$/i.test(segment) || segment.length > 40) {
          return stableMask(segment);
        }
        return segment;
      }).join('/');
      const queryKeys = (match[3] || '').split('&').filter(Boolean).map(function (pair) {
        return decodeURIComponent(pair.split('=')[0]);
      });
      return match[1] + path + (queryKeys.length ? '?<keys:' + queryKeys.join(',') + '>' : '');
    }

    function headersSummary(headers) {
      if (headers === null || headers === undefined) return { names: [], values: {} };
      const names = [];
      const values = {};
      let truncated = false;
      try {
        // OkHttp 4.12 in this R8 build keeps size() but renames name(index)
        // and value(index) to f(index) and k(index). Cast the reflection
        // result so Frida exposes the concrete methods, while retaining the
        // standard-name fallback for less-obfuscated builds.
        let typedHeaders = headers;
        try {
          typedHeaders = Java.cast(headers, Java.use('okhttp3.i'));
        } catch (_) {}
        const size = Number(typedHeaders.size());
        for (let i = 0; i < size; i += 1) {
          if (names.length >= CONFIG.maxBodyKeys) {
            truncated = true;
            break;
          }
          let rawName = null;
          let rawValue = null;
          try { rawName = typedHeaders.name(i); } catch (_) {
            rawName = typedHeaders.f(i);
          }
          try { rawValue = typedHeaders.value(i); } catch (_) {
            rawValue = typedHeaders.k(i);
          }
          const name = safeString(rawName);
          const value = formatHeaderValue(name, rawValue);
          if (values[name] === undefined) {
            names.push(name);
            values[name] = value;
          } else if (Array.isArray(values[name])) {
            values[name].push(value);
          } else {
            values[name] = [values[name], value];
          }
        }
      } catch (e) {
        return { names: names.sort(), values: values, error: String(e) };
      }
      names.sort();
      return { names: names, values: values, truncated: truncated };
    }

    function requestInfo(request) {
      if (request === null || request === undefined) return {};
      let method = null;
      let url = null;
      let headers = null;
      try { method = safeString(request.method()); } catch (_) {}
      try { url = request.url(); } catch (_) {}
      try { headers = request.headers(); } catch (_) {}
      const urlText = safeString(url);
      const hostMatch = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(urlText);
      const routeInfo = normalizedNetworkRoute(urlText, hostMatch ? hostMatch[1] : null);
      return {
        method: method,
        host: hostMatch ? hostMatch[1] : null,
        url: sanitizedUrl(url),
        route: routeInfo.route,
        queryKeys: queryKeyNames(urlText),
        headers: headersSummary(headers),
        requestClass: className(request)
      };
    }

    function responseInfo(response) {
      if (response === null || response === undefined) return {};
      let code = null;
      let message = null;
      let headers = null;
      try { code = response.code(); } catch (_) {
        try { code = response.getCode(); } catch (_) {}
      }
      try { message = safeString(response.message()); } catch (_) {
        try { message = safeString(response.getMessage()); } catch (_) {}
      }
      try { headers = response.headers(); } catch (_) {}
      return {
        code: code,
        message: message,
        headers: headersSummary(headers),
        responseClass: className(response)
      };
    }

    function installOkHttpHooks() {
      install('OkHttp RealCall', function () {
        const RealCall = Java.use('com.quram.mi.ocr.ez11');

        RealCall.$init.overloads.forEach(function (ctor) {
          ctor.implementation = function () {
            const result = ctor.apply(this, arguments);
            const req = arguments.length > 1 ? requestInfo(arguments[1]) : {};
            if (hostAllowed(req.host || '')) {
              const traceId = nextId('http');
              httpCalls[identity(this)] = { traceId: traceId, at: now(), request: req };
              emit('HTTP_CALL_CREATED', traceId, {
                request: req,
                action: recentAction(),
                stack: appStack()
              });
            }
            return result;
          };
        });

        const proceed = RealCall.q.overload();
        proceed.implementation = function () {
          const key = identity(this);
          let meta = httpCalls[key];
          if (!meta) {
            const req = requestInfo(this.request());
            if (!hostAllowed(req.host || '')) return proceed.call(this);
            meta = { traceId: nextId('http'), at: now(), request: req };
            httpCalls[key] = meta;
          }
          emit('HTTP_REQUEST', meta.traceId, {
            request: meta.request,
            action: recentAction(),
            stack: appStack()
          });
          try {
            const response = proceed.call(this);
            emit('HTTP_RESPONSE', meta.traceId, {
              latencyMs: now() - meta.at,
              request: meta.request,
              response: responseInfo(response),
              stack: appStack()
            });
            delete httpCalls[key];
            return response;
          } catch (e) {
            emit('HTTP_FAILURE', meta.traceId, {
              latencyMs: now() - meta.at,
              request: meta.request,
              error: String(e),
              stack: appStack()
            });
            delete httpCalls[key];
            throw e;
          }
        };
      });

      install('OkHttp final wire exchange', function () {
        // CallServerInterceptor is the last interceptor. Its chain contains
        // headers added by application/network interceptors (Authorization,
        // Cookie, User-Agent, Accept-Encoding, and so on), unlike RealCall's
        // originalRequest snapshot.
        const CallServerInterceptor = Java.use('com.quram.mi.ocr.d15');
        const RealInterceptorChain = Java.use('okhttp3.internal.http.RealInterceptorChain');
        const original = CallServerInterceptor.intercept.overload('okhttp3.Interceptor$Chain');

        original.implementation = function (chain) {
          let request = null;
          let call = null;
          try {
            const realChain = Java.cast(chain, RealInterceptorChain);
            request = realChain.getRequest();
            call = realChain.getCall();
          } catch (_) {
            try { request = chain.request(); } catch (_) {}
          }

          const req = requestInfo(request);
          if (!hostAllowed(req.host || '')) return original.call(this, chain);

          const key = call === null ? null : identity(call);
          let meta = key === null ? null : httpCalls[key];
          if (!meta) {
            meta = { traceId: nextId('http'), at: now(), request: req };
            if (key !== null) httpCalls[key] = meta;
          }

          emit('HTTP_WIRE_REQUEST', meta.traceId, {
            request: req,
            action: recentAction()
          });
          try {
            const response = original.call(this, chain);
            emit('HTTP_WIRE_RESPONSE', meta.traceId, {
              latencyMs: now() - meta.at,
              request: req,
              response: responseInfo(response)
            });
            return response;
          } catch (e) {
            emit('HTTP_WIRE_FAILURE', meta.traceId, {
              latencyMs: now() - meta.at,
              request: req,
              error: String(e)
            });
            throw e;
          }
        };
      });
    }

    function binarySummary(value) {
      if (value === null || value === undefined) return { type: 'null', size: 0 };
      let size = null;
      const type = className(value);
      // OkHttp's R8-renamed ByteString is com.quram.mi.ocr.ti4. Its Kotlin
      // size property is exposed as F() (and delegates to k()), not size().
      if (type === 'com.quram.mi.ocr.ti4') {
        try {
          const ByteString = Java.use('com.quram.mi.ocr.ti4');
          const bytes = Java.cast(value, ByteString);
          try { size = Number(bytes.F()); } catch (_) { size = Number(bytes.k()); }
        } catch (_) {}
      }
      if (size === null) {
        try { size = Number(value.size()); } catch (_) {}
      }
      if (size === null) {
        try { size = Number(value.length); } catch (_) {}
      }
      if (size === null) size = safeString(value).length;
      return { type: type, size: size };
    }

    function installWebSocketHooks() {
      const Listener = Java.use('com.quram.mi.ocr.v1j1');
      let TraceListener = null;

      install('OkHttp WebSocket listener bridge', function () {
        TraceListener = Java.registerClass({
          name: 'com.audit.frida.FeatureTraceWebSocketListener_' + bridgeSuffix,
          superClass: Listener,
          fields: {
            delegate: 'com.quram.mi.ocr.v1j1',
            traceId: 'java.lang.String'
          },
          methods: {
            $init: [{
              returnType: 'void',
              argumentTypes: ['com.quram.mi.ocr.v1j1', 'java.lang.String'],
              implementation: function (delegate, traceId) {
                this.$super.$init();
                this.delegate.value = delegate;
                this.traceId.value = traceId;
              }
            }],
            onOpen: [{
              returnType: 'void',
              argumentTypes: ['com.quram.mi.ocr.t1j1', 'okhttp3.Response'],
              implementation: function (socket, response) {
                emit('WEBSOCKET_OPEN', String(this.traceId.value), { response: responseInfo(response) });
                return this.delegate.value.onOpen(socket, response);
              }
            }],
            onMessage: [
              {
                returnType: 'void',
                argumentTypes: ['com.quram.mi.ocr.t1j1', 'java.lang.String'],
                implementation: function (socket, textValue) {
                  emit('WEBSOCKET_RECEIVE', String(this.traceId.value), {
                    payload: CONFIG.rawPayload ? safeString(textValue) : binarySummary(textValue)
                  });
                  return this.delegate.value.onMessage(socket, textValue);
                }
              },
              {
                returnType: 'void',
                argumentTypes: ['com.quram.mi.ocr.t1j1', 'com.quram.mi.ocr.ti4'],
                implementation: function (socket, bytes) {
                  emit('WEBSOCKET_RECEIVE', String(this.traceId.value), { payload: binarySummary(bytes) });
                  return this.delegate.value.onMessage(socket, bytes);
                }
              }
            ],
            onClosing: [{
              returnType: 'void',
              argumentTypes: ['com.quram.mi.ocr.t1j1', 'int', 'java.lang.String'],
              implementation: function (socket, code, reason) {
                emit('WEBSOCKET_CLOSING', String(this.traceId.value), { code: code, reason: formatValue('reason', reason) });
                return this.delegate.value.onClosing(socket, code, reason);
              }
            }],
            onClosed: [{
              returnType: 'void',
              argumentTypes: ['com.quram.mi.ocr.t1j1', 'int', 'java.lang.String'],
              implementation: function (socket, code, reason) {
                emit('WEBSOCKET_CLOSED', String(this.traceId.value), { code: code, reason: formatValue('reason', reason) });
                return this.delegate.value.onClosed(socket, code, reason);
              }
            }],
            onFailure: [{
              returnType: 'void',
              argumentTypes: ['com.quram.mi.ocr.t1j1', 'java.lang.Throwable', 'okhttp3.Response'],
              implementation: function (socket, error, response) {
                emit('WEBSOCKET_FAILURE', String(this.traceId.value), {
                  error: safeString(error),
                  response: responseInfo(response)
                });
                return this.delegate.value.onFailure(socket, error, response);
              }
            }]
          }
        });
      });

      install('OkHttpClient.newWebSocket', function () {
        const Client = Java.use('okhttp3.OkHttpClient');
        const original = Client.newWebSocket.overload(
          'okhttp3.Request',
          'com.quram.mi.ocr.v1j1'
        );
        original.implementation = function (request, listener) {
          const req = requestInfo(request);
          if (!hostAllowed(req.host || '')) return original.call(this, request, listener);
          const traceId = nextId('ws');
          emit('WEBSOCKET_CONNECT', traceId, {
            request: req,
            action: recentAction(),
            stack: appStack()
          });
          const wrapped = TraceListener
            ? TraceListener.$new(listener, JString.$new(traceId))
            : listener;
          const socket = original.call(this, request, wrapped);
          webSockets[identity(socket)] = { traceId: traceId, request: req };
          return socket;
        };
      });

      install('OkHttp WebSocket send', function () {
        const RealWebSocket = Java.use('com.quram.mi.ocr.pz11');
        [
          ['d', 'java.lang.String'],
          ['h', 'com.quram.mi.ocr.ti4']
        ].forEach(function (spec) {
          const original = RealWebSocket[spec[0]].overload(spec[1]);
          original.implementation = function (payload) {
            const meta = webSockets[identity(this)];
            if (meta) {
              emit('WEBSOCKET_SEND', meta.traceId, {
                payload: CONFIG.rawPayload && spec[1] === 'java.lang.String'
                  ? safeString(payload)
                  : binarySummary(payload),
                stack: appStack()
              });
            }
            return original.call(this, payload);
          };
        });
      });
    }

    function installHttpUrlConnectionHooks() {
      function javaMapSummary(mapValue) {
        const names = [];
        const values = {};
        let truncated = false;
        if (mapValue === null || mapValue === undefined) {
          return { names: names, values: values, truncated: truncated };
        }
        try {
          const JavaMap = Java.use('java.util.Map');
          const map = Java.cast(mapValue, JavaMap);
          const iterator = map.entrySet().iterator();
          while (iterator.hasNext()) {
            if (names.length >= CONFIG.maxBodyKeys) {
              truncated = true;
              break;
            }
            const entry = iterator.next();
            const name = safeString(entry.getKey());
            names.push(name);
            values[name] = formatHeaderValue(name, entry.getValue());
          }
        } catch (e) {
          return { names: names.sort(), values: values, error: String(e) };
        }
        names.sort();
        return { names: names, values: values, truncated: truncated };
      }

      install('java.net.URL.openConnection', function () {
        const URL = Java.use('java.net.URL');
        URL.openConnection.overloads.forEach(function (original) {
          original.implementation = function () {
            const url = safeString(this);
            const schemeMatch = /^([a-z][a-z0-9+.-]*):/i.exec(url);
            const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : null;
            if (CONFIG.commonEvidence.networkSchemesOnly &&
                scheme !== 'http' && scheme !== 'https') {
              return original.apply(this, arguments);
            }
            const hostMatch = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(url);
            if (!hostAllowed(hostMatch ? hostMatch[1] : '')) {
              return original.apply(this, arguments);
            }

            const traceId = nextId('url');
            const at = now();
            const action = recentAction();
            const routeInfo = normalizedNetworkRoute(url, hostMatch ? hostMatch[1] : null);
            const queryKeys = queryKeyNames(url);
            try {
              const connection = original.apply(this, arguments);
              urlConnections[identity(connection)] = {
                traceId: traceId,
                at: at,
                url: sanitizedUrl(this),
                route: routeInfo.route,
                queryKeys: queryKeys,
                action: action
              };
              emit('URL_CONNECTION_OPEN', traceId, {
                url: sanitizedUrl(this),
                route: routeInfo.route,
                queryKeys: queryKeys,
                connectionClass: className(connection),
                action: action,
                stack: appStack()
              });
              return connection;
            } catch (e) {
              emit('URL_CONNECTION_FAILURE', traceId, {
                url: sanitizedUrl(this),
                error: String(e)
              });
              throw e;
            }
          };
        });
      });

      [
        'com.android.okhttp.internal.huc.HttpURLConnectionImpl',
        'com.android.okhttp.internal.huc.HttpsURLConnectionImpl'
      ].forEach(function (candidate) {
        install(candidate + '.getResponseCode', function () {
          const Connection = Java.use(candidate);
          const original = Connection.getResponseCode.overload();
          original.implementation = function () {
            // Android HTTPS delegates to an internal HTTP connection. Both
            // candidate hooks can therefore run for one public call; let the
            // outer hook own the event pair and suppress the nested duplicate.
            const activeKey = identity(Thread.currentThread());
            if (activeUrlResponses[activeKey]) return original.call(this);

            const key = identity(this);
            let meta = urlConnections[key];
            if (!meta) {
              let connectionUrl = null;
              try { connectionUrl = sanitizedUrl(this.getURL()); } catch (_) {}
              meta = {
                traceId: nextId('url'),
                at: now(),
                url: connectionUrl,
                route: normalizedNetworkRoute(connectionUrl, null).route,
                queryKeys: queryKeyNames(connectionUrl),
                action: recentAction()
              };
              urlConnections[key] = meta;
            }
            activeUrlResponses[activeKey] = meta;
            let requestMethod = null;
            let requestHeaders = null;
            try { requestMethod = safeString(this.getRequestMethod()); } catch (_) {}
            try { requestHeaders = this.getRequestProperties(); } catch (_) {}
            meta.method = requestMethod;
            emit('URL_CONNECTION_REQUEST', meta.traceId, {
              url: meta.url,
              route: meta.route,
              queryKeys: meta.queryKeys,
              method: requestMethod,
              headers: javaMapSummary(requestHeaders),
              action: meta.action,
              stack: appStack()
            });
            try {
              const code = original.call(this);
              let responseHeaders = null;
              try { responseHeaders = this.getHeaderFields(); } catch (_) {}
              emit('URL_CONNECTION_RESPONSE', meta.traceId, {
                latencyMs: now() - meta.at,
                url: meta.url,
                route: meta.route,
                queryKeys: meta.queryKeys,
                method: meta.method,
                code: code,
                headers: javaMapSummary(responseHeaders)
              });
              delete urlConnections[key];
              delete activeUrlResponses[activeKey];
              return code;
            } catch (e) {
              emit('URL_CONNECTION_FAILURE', meta.traceId, {
                latencyMs: now() - meta.at,
                url: meta.url,
                route: meta.route,
                queryKeys: meta.queryKeys,
                method: meta.method,
                error: String(e)
              });
              delete urlConnections[key];
              delete activeUrlResponses[activeKey];
              throw e;
            }
          };
        });
      });
    }

    function mapKeys(map) {
      const keys = [];
      if (map === null || map === undefined) return keys;
      try {
        const iterator = map.keySet().iterator();
        while (iterator.hasNext() && keys.length < CONFIG.maxBodyKeys) {
          keys.push(String(iterator.next()));
        }
      } catch (_) {}
      return keys.sort();
    }

    function installFcmHooks() {
      install('FcmMessagingService messages/tokens', function () {
        const Service = Java.use('com.kakao.talk.core.loco.fcm.FcmMessagingService');

        const message = Service.p.overload('com.google.firebase.messaging.RemoteMessage');
        message.implementation = function (remoteMessage) {
          const traceId = nextId('fcm');
          const data = callNoArg(remoteMessage, ['F1', 'getData']);
          const from = safeString(callNoArg(remoteMessage, ['R1', 'getFrom']));
          const messageId = safeString(callNoArg(remoteMessage, ['b1', 'getMessageId']));
          const detail = {
            from: CONFIG.rawPayload ? from : stableMask(from),
            messageId: CONFIG.rawPayload ? messageId : stableMask(messageId),
            dataKeys: mapKeys(data),
            stack: appStack()
          };
          if (CONFIG.rawPayload) detail.data = safeString(data);
          emit('FCM_MESSAGE', traceId, detail);

          // p() calls v(content) synchronously. Keep the message trace on the
          // current thread so the decrypted content event shares the same ID.
          const activeKey = identity(Thread.currentThread());
          activeFcmMessages[activeKey] = traceId;
          try {
            return message.call(this, remoteMessage);
          } finally {
            delete activeFcmMessages[activeKey];
          }
        };

        const decrypt = Service.v.overload('java.lang.String');
        decrypt.implementation = function (content) {
          const activeKey = identity(Thread.currentThread());
          const traceId = activeFcmMessages[activeKey] || nextId('fcm');
          let decrypted;
          try {
            decrypted = decrypt.call(this, content);
          } catch (e) {
            emit('FCM_CONTENT_DECRYPT_FAILURE', traceId, { error: String(e) });
            throw e;
          }
          const inputText = safeString(content);
          const outputText = decrypted === null ? null : safeString(decrypted);
          emit('FCM_CONTENT_DECRYPTED', traceId, {
            encryptedContent: CONFIG.rawPayload
              ? inputText
              : '<redacted len=' + inputText.length + '>',
            decryptedContent: outputText === null
              ? null
              : (CONFIG.rawPayload
                ? outputText
                : '<redacted len=' + outputText.length + '>'),
            success: decrypted !== null
          });
          return decrypted;
        };

        const token = Service.r.overload('java.lang.String');
        token.implementation = function (newToken) {
          const tokenValue = safeString(newToken);
          emit('FCM_TOKEN_REFRESH', nextId('fcm'), {
            token: CONFIG.rawPayload
              ? tokenValue
              : '<redacted len=' + tokenValue.length + '>'
          });
          return token.call(this, newToken);
        };
      });
    }

    function installProtobufHooks() {
      install('Protocol Buffers serialization', function () {
        let MessageLite;
        try {
          MessageLite = Java.use('com.google.protobuf.AbstractMessageLite');
        } catch (_) {
          // KakaoTalk 26.7.1 R8-renames AbstractMessageLite to this class.
          MessageLite = Java.use('com.google.protobuf.a');
        }
        const original = MessageLite.toByteArray.overload();
        original.implementation = function () {
          const lines = fullStack();
          const bytes = original.call(this);
          if (hasAppFrame(lines)) {
            emit('PROTOBUF_SERIALIZE', nextId('proto'), {
              messageClass: className(this),
              byteLength: bytes ? bytes.length : 0,
              stack: lines.filter(function (line) {
                return CONFIG.appStackPrefixes.some(function (prefix) {
                  return line.indexOf(prefix) !== -1;
                });
              }).slice(0, CONFIG.stackFrames)
            });
          }
          return bytes;
        };
      });
    }

    if (CONFIG.modules.ui) installUiHooks();
    if (CONFIG.modules.lifecycle) installLifecycleHooks();
    if (CONFIG.modules.observableState) installObservableStateHooks();
    if (CONFIG.modules.loco) installLocoHooks();
    if (CONFIG.modules.okhttp) installOkHttpHooks();
    if (CONFIG.modules.webSocket) installWebSocketHooks();
    if (CONFIG.modules.httpUrlConnection) installHttpUrlConnectionHooks();
    if (CONFIG.modules.fcm) installFcmHooks();
    if (CONFIG.modules.protobuf) installProtobufHooks();

    emit('READY', '-', {
      commonSchema: CONFIG.schemaVersion,
      commonSummaryRpc: [
        'get_common_summary',
        'emit_common_summary',
        'reset_common_summary',
        'mark_user_action'
      ],
      rawPayload: CONFIG.rawPayload,
      commonEvidence: CONFIG.commonEvidence,
      fieldCoverage: commonSummary.fieldCoverage,
      modules: CONFIG.modules,
      filters: CONFIG.filters
    });
  });
}

setImmediate(startTracer);
