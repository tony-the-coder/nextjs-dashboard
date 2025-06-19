// auth.ts



import NextAuth from 'next-auth';

import Credentials from 'next-auth/providers/credentials';

import { authConfig } from './auth.config';

import { z } from 'zod';

import type { User } from '@/app/lib/definitions';

import bcrypt from 'bcrypt';

import postgres from 'postgres';

 

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

 

async function getUser(email: string): Promise<User | undefined> {

  try {

    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;

    // console.log('getUser result:', user); // Add this for debugging

    return user[0];

  } catch (error) {

    console.error('Failed to fetch user:', error);

    throw new Error('Failed to fetch user.');

  }

}

 

export const { auth, signIn, signOut } = NextAuth({

  ...authConfig,

  providers: [

    Credentials({

      async authorize(credentials) {

        const parsedCredentials = z

          .object({ email: z.string().email(), password: z.string().min(6) })

          .safeParse(credentials);

 

        if (parsedCredentials.success) {

          const { email, password } = parsedCredentials.data;

          // console.log('Attempting login for email:', email); // Add this for debugging

          const user = await getUser(email);

          // console.log('User found in authorize:', user); // Add this for debugging



          if (!user) {

            console.log('No user found with that email.'); // Debug specific failure point

            return null;

          }

          const passwordsMatch = await bcrypt.compare(password, user.password);

          // console.log('Password from form:', password); // Debug

          // console.log('Hashed password from DB:', user.password); // Debug

          // console.log('Passwords match result:', passwordsMatch); // Debug



          if (passwordsMatch) {

            return user; // Authentication successful

          }

        }

 

        console.log('Invalid credentials'); // This log indicates failure

        return null;

      },

    }),

  ],

});