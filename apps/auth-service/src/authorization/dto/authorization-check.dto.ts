import { IsIn, IsOptional, IsString, IsUUID, MaxLength, MinLength } from 'class-validator';
export class AuthorizationCheckDto {
  @IsString() @MinLength(1) @MaxLength(4096) subject_token!: string;
  @IsIn(['steganography.analyze', 'steganography.results.read']) action!: string;
  @IsOptional() @IsUUID() resource_id?: string;
}
