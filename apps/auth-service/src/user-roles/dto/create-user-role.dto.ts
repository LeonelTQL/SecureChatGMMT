import { IsUUID } from 'class-validator';
export class CreateUserRoleDto {
  @IsUUID() user_id!: string;
  @IsUUID() role_id!: string;
}
