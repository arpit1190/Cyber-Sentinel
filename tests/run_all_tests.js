/**
 * tests/run_all_tests.js
 * Master Automated Test Suite Runner for Cyber Sentinel.
 * Executes all Unit, Integration, Security, and E2E test suites with structured timing and reporting.
 */

const { runAuthUnitTests } = require('./unit/auth.test');
const { runJwtUnitTests } = require('./unit/jwt.test');
const { runValidationUnitTests } = require('./unit/validation.test');
const { runDetectionRulesUnitTests } = require('./unit/detectionRules.test');
const { runMitreMappingUnitTests } = require('./unit/mitreMapping.test');
const { runThreatIntelUnitTests } = require('./unit/threatIntel.test');
const { runPrivacyTests } = require('./unit/privacy.test');

const { runDeviceLifecycleIntegrationTests } = require('./integration/deviceLifecycle.test');
const { runTelemetryIngestionIntegrationTests } = require('./integration/telemetryIngestion.test');
const { runIncidentWorkflowIntegrationTests } = require('./integration/incidentWorkflow.test');
const { runAuditLogsIntegrationTests } = require('./integration/auditLogs.test');
const { runDatabaseIntegrationTests } = require('./integration/databaseIntegration.test');
const { runDisasterRecoveryTests } = require('./unit/disasterRecovery.test');

const { runAiSecurityTests } = require('./security/aiSecurity.test');
const { runResponseAuthorizationSecurityTests } = require('./security/responseAuthorization.test');
const { runFileUploadSecurityTests } = require('./security/fileUploadSecurity.test');
const { runRateLimitingSecurityTests } = require('./security/rateLimiting.test');
const { runRegressionAuditSecurityTests } = require('./security/regressionAudit.test');
const { runAdversarialTestSuite } = require('./security/adversarialSuite.test');

const { runSocPipelineE2ETests } = require('./e2e/socPipelineE2E.test');

async function runAllSuites() {
  const startTime = Date.now();
  console.log('\n======================================================================');
  console.log('🛡️   CYBER SENTINEL — COMPREHENSIVE AUTOMATED TEST SUITE');
  console.log('======================================================================');

  let totalPassed = 0;
  let totalFailed = 0;

  const categories = [
    {
      name: 'UNIT TESTS',
      suites: [
        { name: 'Authentication & Password Security', fn: runAuthUnitTests },
        { name: 'JWT & Cryptographic Tokens', fn: runJwtUnitTests },
        { name: 'Input Validation & Normalization', fn: runValidationUnitTests },
        { name: 'Data Privacy & Minimization', fn: runPrivacyTests },
        { name: 'Detection Rules & Engine', fn: runDetectionRulesUnitTests },
        { name: 'MITRE ATT&CK Mapping', fn: runMitreMappingUnitTests },
        { name: 'Threat Intelligence & IOCs', fn: runThreatIntelUnitTests },
      ],
    },
    {
      name: 'INTEGRATION TESTS',
      suites: [
        { name: 'Device Lifecycle & Credentials', fn: runDeviceLifecycleIntegrationTests },
        { name: 'Telemetry Ingestion & HMAC Signatures', fn: runTelemetryIngestionIntegrationTests },
        { name: 'Incident Workflow & Timeline Chain', fn: runIncidentWorkflowIntegrationTests },
        { name: 'Immutable Audit Logging', fn: runAuditLogsIntegrationTests },
        { name: 'Database Repository Parameterization', fn: runDatabaseIntegrationTests },
        { name: 'Disaster Recovery & Backup Restoration', fn: runDisasterRecoveryTests },
      ],
    },
    {
      name: 'SECURITY & ADVERSARIAL TESTS',
      suites: [
        { name: 'AI Security & Prompt Injection', fn: runAiSecurityTests },
        { name: 'Response Action Authorization & FSM', fn: runResponseAuthorizationSecurityTests },
        { name: 'File Upload & Quarantine Security', fn: runFileUploadSecurityTests },
        { name: 'Rate Limiting & DoS Protection', fn: runRateLimitingSecurityTests },
        { name: 'Security Audit Regression Suite', fn: runRegressionAuditSecurityTests },
        { name: 'Comprehensive Adversarial & Resilience Suite', fn: runAdversarialTestSuite },
      ],
    },
    {
      name: 'END-TO-END (E2E) TESTS',
      suites: [
        { name: 'Full Operational SOC Pipeline', fn: runSocPipelineE2ETests },
      ],
    },
  ];

  for (const cat of categories) {
    console.log(`\n\x1b[1m\x1b[36m▶ CATEGORY: ${cat.name}\x1b[0m`);
    for (const suite of cat.suites) {
      try {
        const res = await suite.fn();
        if (res) {
          totalPassed += res.passed || 0;
          totalFailed += res.failed || 0;
        }
      } catch (err) {
        console.error(`  ❌ Suite Execution Error in [${suite.name}]: ${err.message}`);
        totalFailed++;
      }
    }
  }

  const elapsedSec = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log('\n======================================================================');
  console.log('🏁  FINAL AUTOMATED TEST EXECUTION SUMMARY');
  console.log('======================================================================');
  console.log(`  ⏱️  Total Duration : ${elapsedSec}s`);
  console.log(`  ✅ Total Passed   : \x1b[32m${totalPassed}\x1b[0m`);
  console.log(`  ❌ Total Failed   : \x1b[31m${totalFailed}\x1b[0m`);
  console.log('======================================================================\n');

  if (totalFailed > 0) {
    console.error(`\x1b[31m[FAILED] Test suite completed with ${totalFailed} failure(s).\x1b[0m\n`);
    process.exit(1);
  } else {
    console.log(`\x1b[32m[SUCCESS] All Cyber Sentinel test suites passed with 100% success rate!\x1b[0m\n`);
    process.exit(0);
  }
}

if (require.main === module) {
  runAllSuites();
}

module.exports = { runAllSuites };
