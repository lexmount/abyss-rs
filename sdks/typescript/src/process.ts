/** Runtime entry shared by TLS selectors and plugin source metadata. */
export type ProcessEntry =
  | { readonly kind: "script"; readonly path: string }
  | {
      readonly kind: "module";
      readonly runtime: "python";
      readonly name: string;
    };
