import { Transform } from 'class-transformer';
import { IsString, Matches } from 'class-validator';
import { LoginDto } from '../../auth/dto/login.dto/login.dto';
import { normalized } from '../../common/dto/normalize';
export class CreateUserDto extends LoginDto {
  @Transform(normalized) @IsString() @Matches(/^[a-z0-9._-]{3,50}$/) username!: string;
}
