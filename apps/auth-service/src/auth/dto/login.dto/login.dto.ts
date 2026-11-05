import { Transform } from 'class-transformer';
import { IsEmail, IsString, Matches, MaxLength, MinLength } from 'class-validator';
import { normalized } from '../../../common/dto/normalize';
export class LoginDto {
  @Transform(normalized) @IsEmail() @MaxLength(254) email!: string;
  @IsString() @MinLength(12) @MaxLength(128)
  @Matches(/\S/, { message: 'La contraseña debe contener un carácter no blanco' }) password!: string;
}
