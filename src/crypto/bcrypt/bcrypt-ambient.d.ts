declare module "bcrypt" {
  export function hash(
    password: string,
    saltOrRounds: string | number,
  ): Promise<string>;
  export function compare(password: string, hash: string): Promise<boolean>;
  export function getRounds(hash: string): number;
}
