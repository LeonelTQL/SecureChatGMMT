import { IsBoolean, IsString, MaxLength, MinLength, ValidateIf } from 'class-validator';
export class UpdateRoleDto {
  @ValidateIf((_, value) => value !== undefined) @IsString() @MinLength(1) @MaxLength(250) description?: string;
  @ValidateIf((_, value) => value !== undefined) @IsBoolean() status?: boolean;
}
