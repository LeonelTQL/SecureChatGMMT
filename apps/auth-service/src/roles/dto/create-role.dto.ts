import { IsIn, IsString, MaxLength, MinLength } from 'class-validator';
export class CreateRoleDto {
  @IsIn(['ADMIN', 'ANALYST', 'USER']) name!: string;
  @IsString() @MinLength(1) @MaxLength(250) description!: string;
}
