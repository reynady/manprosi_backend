export function buildRepo(db){
  return {
    async listByLand(landId){
      if(landId){
        const [rows] = await db.execute('SELECT * FROM recommendations WHERE land_id = ? ORDER BY created_at DESC',[landId]);
        return rows;
      }
      const [rows] = await db.execute('SELECT * FROM recommendations ORDER BY created_at DESC');
      return rows;
    },
    async findById(id){
      const [rows] = await db.execute('SELECT * FROM recommendations WHERE id = ?', [id]);
      return rows[0] ?? null;
    },
    async insert(payload){
      // payload: { land_id?, name, description, rec_type?, seed_id?, created_by? }
      const cols = [];
      const params = [];
      if('land_id' in payload){ cols.push('land_id'); params.push(payload.land_id); }
      cols.push('name'); params.push(payload.name);
      cols.push('description'); params.push(payload.description);
      if('rec_type' in payload){ cols.push('rec_type'); params.push(payload.rec_type); }
      if('seed_id' in payload){ cols.push('seed_id'); params.push(payload.seed_id); }
      if('created_by' in payload){ cols.push('created_by'); params.push(payload.created_by); }
      const placeholders = cols.map(_=>'?').join(',');
      const sql = `INSERT INTO recommendations (${cols.join(',')}) VALUES (${placeholders})`;
      const [result] = await db.execute(sql, params);
      return { id: result.insertId, ...payload };
    },
    async update(id, fields){
      const cols = [];
      const params = [];
      for(const k of Object.keys(fields)){
        cols.push(`${k} = ?`);
        params.push(fields[k]);
      }
      params.push(id);
      const sql = `UPDATE recommendations SET ${cols.join(', ')} WHERE id = ?`;
      await db.execute(sql, params);
      return this.findById(id);
    },
    async remove(id){
      await db.execute('DELETE FROM recommendations WHERE id = ?', [id]);
      return true;
    }
  }
}
