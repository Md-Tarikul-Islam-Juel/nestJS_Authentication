-- CreateTable
CREATE TABLE "users" (
    "id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "firstName" TEXT,
    "lastName" TEXT,
    "loginSource" TEXT NOT NULL DEFAULT 'default',
    "authorizerId" TEXT,
    "verified" BOOLEAN NOT NULL,
    "isForgetPassword" BOOLEAN NOT NULL,
    "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "failedOtpAttempts" INTEGER NOT NULL DEFAULT 0,
    "accountLockedUntil" TIMESTAMP(3),
    "lastActivityAt" TIMESTAMP(3),
    "logoutPin" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");
