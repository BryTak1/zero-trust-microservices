export type Document = {
  readonly id: string;
  readonly title: string;
  readonly body: string;
  readonly createdBy: string;
};

export type DocumentRepository = {
  readonly list: () => Promise<readonly Document[]>;
  readonly findById: (id: string) => Promise<Document | undefined>;
  readonly insert: (document: Document) => Promise<void>;
  // Resolves to false when no such document existed.
  readonly remove: (id: string) => Promise<boolean>;
};

export const createInMemoryDocumentRepository = (
  seed: readonly Document[] = [],
): DocumentRepository => {
  const documents = new Map(seed.map((document) => [document.id, document]));
  return {
    list: async () => [...documents.values()],
    findById: async (id) => documents.get(id),
    insert: async (document) => {
      documents.set(document.id, document);
    },
    remove: async (id) => documents.delete(id),
  };
};
