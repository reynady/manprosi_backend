export function buildService(repo){
  return {
    async list(landId){
      return repo.listByLand(landId);
    },
    async get(id){
      return repo.findById(id);
    },
    async create(payload){
      // basic business rule: name+description required
      if(!payload.name || !payload.description) throw { status:400, message:'Missing required fields' };
      return repo.insert(payload);
    },
    async update(id, fields){
      const existing = await repo.findById(id);
      if(!existing) throw { status:404, message:'Recommendation not found' };
      return repo.update(id, fields);
    },
    async delete(id){
      const existing = await repo.findById(id);
      if(!existing) throw { status:404, message:'Recommendation not found' };
      await repo.remove(id);
      return true;
    }
  }
}
