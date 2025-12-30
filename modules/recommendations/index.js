import express from 'express';
import { body, validationResult } from 'express-validator';
import { buildRepo } from './repo.js';
import { buildService } from './service.js';

function createErrorResponse(res, err) {
  if (err && err.status) return res.status(err.status).json({ success: false, error: err.message });
  return res.status(500).json({ success: false, error: String(err?.message || err) });
}

export default function makeRecommendationsRouter(db) {
  const router = express.Router();
  const repo = buildRepo(db);
  const service = buildService(repo);

  // list
  router.get('/', async (req, res) => {
    try {
      const land_id = req.query.land_id;
      const rows = await service.list(land_id);
      return res.json({ success: true, data: rows });
    } catch (e) { return createErrorResponse(res, e); }
  });

  // create (validators)
  router.post('/', [
    body('name').isString().notEmpty(),
    body('description').isString().notEmpty(),
    body('land_id').optional().isInt(),
    body('rec_type').optional().isString(),
    body('seed_id').optional().isInt(),
  ], async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ success: false, error: 'validation', details: errors.array() });

      // RBAC: allow consultant or admin
      const roleName = (req.user.role || '').toLowerCase();
      if (req.user.user_role_id !== 1 && roleName !== 'consultant') return res.status(403).json({ success: false, error: 'Forbidden' });

      const payload = {
        land_id: req.body.land_id || null,
        name: req.body.name,
        description: req.body.description,
        rec_type: req.body.rec_type || null,
        seed_id: req.body.seed_id || null,
      };

      // Assumes created_by column exists (initialized in db.js)
      payload.created_by = req.user.id;

      const created = await service.create(payload);
      return res.json({ success: true, data: created });
    } catch (e) { return createErrorResponse(res, e); }
  });

  // get
  router.get('/:id', async (req, res) => {
    try {
      const rec = await service.get(req.params.id);
      if (!rec) return res.status(404).json({ success: false, error: 'Recommendation not found' });
      return res.json({ success: true, data: rec });
    } catch (e) { return createErrorResponse(res, e); }
  });

  // update
  router.put('/:id', [
    body('name').optional().isString(),
    body('description').optional().isString(),
    body('rec_type').optional().isString(),
    body('seed_id').optional().isInt(),
  ], async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ success: false, error: 'validation', details: errors.array() });

      const roleName = (req.user.role || '').toLowerCase();

      const existing = await service.get(req.params.id);
      if (!existing) return res.status(404).json({ success: false, error: 'Recommendation not found' });

      if (req.user.user_role_id !== 1 && roleName !== 'consultant') {
        // Check created_by ownership if not admin/consultant
        if (existing.created_by !== req.user.id) return res.status(403).json({ success: false, error: 'Forbidden' });
      }

      const fields = {};
      ['name', 'description', 'rec_type', 'seed_id'].forEach(k => { if (k in req.body) fields[k] = req.body[k]; });
      const updated = await service.update(req.params.id, fields);
      return res.json({ success: true, data: updated });
    } catch (e) { return createErrorResponse(res, e); }
  });

  // delete
  router.delete('/:id', async (req, res) => {
    try {
      const roleName = (req.user.role || '').toLowerCase();

      const existing = await service.get(req.params.id);
      if (!existing) return res.status(404).json({ success: false, error: 'Recommendation not found' });

      if (req.user.user_role_id !== 1 && roleName !== 'consultant') {
        if (existing.created_by !== req.user.id) return res.status(403).json({ success: false, error: 'Forbidden' });
      }

      await service.delete(req.params.id);
      return res.json({ success: true });
    } catch (e) { return createErrorResponse(res, e); }
  });

  return router;
}
