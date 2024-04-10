import {ApiProperty} from "@nestjs/swagger";

export class MeUserData {
    @ApiProperty({ description: 'User ID', example: 1 })
    id: number;

    @ApiProperty({ description: 'User email', example: 'user@gmail.com' })
    email: string;

    @ApiProperty({ description: 'User first name', example: 'user' })
    firstName: string;

    @ApiProperty({ description: 'User last name', example: 'user' })
    lastName: string;
}
export class MeSuccessResponseDto {
    @ApiProperty({ description: 'Indicates if the request was successful', example: true })
    success: boolean;

    @ApiProperty({ description: 'Data of the user', type: MeUserData })
    data: MeUserData;
}
