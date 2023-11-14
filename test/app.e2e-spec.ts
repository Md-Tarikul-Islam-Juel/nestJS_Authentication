import { Test } from '@nestjs/testing';
import { AppModule } from 'src/app.module';

describe('App e2e', () => {
  beforeAll(async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
  });
  it.todo('should pass');
});
