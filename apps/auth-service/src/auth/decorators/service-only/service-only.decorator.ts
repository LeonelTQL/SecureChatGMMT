import { SetMetadata } from '@nestjs/common';
export const SERVICE_ONLY_KEY = 'service';
export const ServiceOnly = () => SetMetadata(SERVICE_ONLY_KEY, true);
