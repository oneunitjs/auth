import { BcryptPasswordHasher } from "../password-hasher.js";
import { BcryptNodeBinding, isBcryptAvailable } from "./binding.js";

/**
 * Create an official {@link BcryptPasswordHasher} backed by the optional
 * `bcrypt` package, with no custom binding required.
 *
 * Throws a clear error on first use when `bcrypt` is not installed. Use
 * {@link isBcryptAvailable} to probe before calling.
 *
 * @param rounds - bcrypt cost factor, in [10, 14]. Defaults to 12.
 */
export function createBcryptPasswordHasher(rounds = 12): BcryptPasswordHasher {
  return new BcryptPasswordHasher(new BcryptNodeBinding(), rounds);
}

export { BcryptNodeBinding, isBcryptAvailable };
