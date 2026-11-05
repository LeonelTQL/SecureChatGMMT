import { Transform } from 'class-transformer';
import { IsBoolean, IsEmail, IsString, Matches, MaxLength, ValidateIf } from 'class-validator';
import { normalized } from '../../common/dto/normalize';
export class UpdateUserDto {
  @ValidateIf((_, value) => value !== undefined) @Transform(normalized) @IsString() @Matches(/^[a-z0-9._-]{3,50}$/) username?: string;
  @ValidateIf((_, value) => value !== undefined) @Transform(normalized) @IsEmail() @MaxLength(254) email?: string;
  @ValidateIf((_, value) => value !== undefined) @IsBoolean() status?: boolean;
}
