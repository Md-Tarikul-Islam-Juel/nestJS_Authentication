import {HttpException, HttpStatus, Injectable} from '@nestjs/common';
import {PrismaService} from "../../prisma/prisma.service";


@Injectable()
export class UserService {
    constructor(
        private readonly prisma: PrismaService,
    ) {
    }

    async me(req: any) {
        try {
            const user = await this.prisma.user.findUnique({
                where: {
                    email: req.user.email,
                },
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                },
            });

            if (!user) {
                throw new HttpException('User not found', HttpStatus.NOT_FOUND);
            }

            return {success: true, data: user};
        } catch (error) {
            throw new HttpException('An error occurred while retrieving user data.', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
