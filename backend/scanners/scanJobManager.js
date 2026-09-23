const EventEmitter = require('events');

/**
 * Scan Job Progress Manager
 * Tracks real-time pipeline execution across static, structural, behavioral, and AI stages.
 * Emits events for WebSockets / Server-Sent Events (SSE) and supports polling.
 */
class ScanJobManager extends EventEmitter {
  constructor() {
    super();
    this.jobs = new Map();
    // Prune jobs older than 15 minutes
    setInterval(() => this.pruneStaleJobs(), 60000);
  }

  createJob(jobId, meta = {}) {
    const job = {
      jobId,
      status: 'INITIALIZING',
      progressPercent: 5,
      currentStage: 'INITIALIZING',
      stageDetails: 'Job registered with security orchestrator',
      stages: [
        { id: 'HASH_SIGNATURES', name: 'Header Signatures & Magic Bytes', status: 'PENDING', percent: 15 },
        { id: 'STRUCTURAL_ANALYSIS', name: 'Structural Chunks & Polyglot Parsing', status: 'PENDING', percent: 35 },
        { id: 'STEGO_ENTROPY', name: 'LSB Steganography & Shannon Entropy', status: 'PENDING', percent: 55 },
        { id: 'BEHAVIORAL_SANDBOX', name: 'Isolated Behavioral Trace & Emulation', status: 'PENDING', percent: 75 },
        { id: 'AI_REASONING', name: 'Gemini Multimodal Threat Reasoning', status: 'PENDING', percent: 90 },
        { id: 'EVIDENCE_FUSION', name: 'Multi-Layer Evidence Fusion & Verdict', status: 'PENDING', percent: 100 }
      ],
      result: null,
      error: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      meta
    };
    this.jobs.set(jobId, job);
    this.emit(`update:${jobId}`, job);
    return job;
  }

  getJob(jobId) {
    return this.jobs.get(jobId);
  }

  updateStage(jobId, stageId, details = '', isComplete = false) {
    const job = this.jobs.get(jobId);
    if (!job) return;

    job.status = 'RUNNING';
    job.currentStage = stageId;
    job.stageDetails = details;
    job.updatedAt = Date.now();

    let targetPercent = job.progressPercent;
    job.stages.forEach(s => {
      if (s.id === stageId) {
        s.status = isComplete ? 'DONE' : 'ACTIVE';
        s.details = details;
        targetPercent = s.percent;
      } else if (job.stages.findIndex(x => x.id === s.id) < job.stages.findIndex(x => x.id === stageId)) {
        s.status = 'DONE';
      }
    });

    job.progressPercent = targetPercent;
    this.emit(`update:${jobId}`, job);
  }

  completeJob(jobId, result) {
    const job = this.jobs.get(jobId);
    if (!job) return;

    job.status = 'COMPLETE';
    job.currentStage = 'COMPLETED';
    job.stageDetails = 'Scan pipeline completed successfully';
    job.progressPercent = 100;
    job.stages.forEach(s => { s.status = 'DONE'; });
    job.result = result;
    job.updatedAt = Date.now();

    this.emit(`update:${jobId}`, job);
    this.emit(`complete:${jobId}`, job);
  }

  failJob(jobId, errorMsg) {
    const job = this.jobs.get(jobId);
    if (!job) return;

    job.status = 'FAILED';
    job.error = errorMsg;
    job.stageDetails = `Scan failed: ${errorMsg}`;
    job.updatedAt = Date.now();

    this.emit(`update:${jobId}`, job);
    this.emit(`error:${jobId}`, job);
  }

  pruneStaleJobs() {
    const now = Date.now();
    for (const [id, job] of this.jobs.entries()) {
      if (now - job.updatedAt > 15 * 60 * 1000) {
        this.jobs.delete(id);
      }
    }
  }
}

const scanJobManager = new ScanJobManager();

module.exports = {
  ScanJobManager,
  scanJobManager
};
