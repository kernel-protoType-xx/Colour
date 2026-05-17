'use strict';

const verifier    = require('./verifier');
const audit       = require('./audit');
const interceptor = require('./interceptor');

module.exports = {
  verifyPackage        : verifier.verifyPackage,
  checkTyposquat       : verifier.checkTyposquat,
  computeProvenanceHash: verifier.computeProvenanceHash,
  levenshtein          : verifier.levenshtein,
  SEVERITY             : verifier.SEVERITY,
  BUNDLED_THREATS      : verifier.BUNDLED_THREATS,
  intercept            : interceptor.intercept,
  parsePackageArg      : interceptor.parsePackageArg,
  detectEcosystem      : interceptor.detectEcosystem,
  extractPackages      : interceptor.extractPackages,
  logVerification      : audit.logVerification,
  readAuditLog         : audit.readAuditLog,
  getAuditSummary      : audit.getAuditSummary,
  verifyAuditChain     : audit.verifyAuditChain,
  exportAuditReport    : audit.exportAuditReport,
  clearAuditLog        : audit.clearAuditLog,
  AUDIT_FILE           : audit.AUDIT_FILE,
  AUDIT_DIR            : audit.AUDIT_DIR,
};
