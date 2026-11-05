import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth/auth.service';
import { AuthorizationCheckDto } from './dto/authorization-check.dto';
import { audit } from '../common/audit/audit';
@Injectable()
export class AuthorizationService {
  constructor(private readonly auth: AuthService) {}
  async check(dto: AuthorizationCheckDto) {
    const identity = await this.auth.verify(dto.subject_token);
    const allowed = identity.roles.some(role => ['ADMIN', 'ANALYST'].includes(role));
    const decision = { subject_id: identity.sub, action: dto.action, resource_id: dto.resource_id ?? null, allowed,
      reason: allowed ? 'active_role_grants_permission' : 'insufficient_privileges',
      scope: identity.roles.includes('ADMIN') ? 'all' : 'own' };
    audit('authorization.decision', { user_id: identity.sub, action: dto.action, resource_id: dto.resource_id, allowed });
    return decision;
  }
}
