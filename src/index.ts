type ABACContext = {
  user: {
    id: string;
    roles: string[];
  };
  resource: {
    ownerId: string;
  };
  action: "read" | "write" | "edit" | "delete";
  environment: {
    ip: string;
    timestamp: Date;
  };
};

type Operator =
  | "equals"
  | "not_equal"
  | "contains"
  | "greater_than"
  | "greater_than_or_equal"
  | "less_than"
  | "less_than_or_equal"
  | "in"
  | "not_in";

type BaseCondition = {
  attribute: string;
  operator: Operator;
  value: any;
};

type AndCondition = {
  and: Condition[];
};

type OrCondition = {
  or: Condition[];
};

type NotCondition = {
  not: Condition;
};

type Condition = BaseCondition | AndCondition | OrCondition | NotCondition;

type Policy = {
  effect: "allow" | "deny";
  name: string;
  description: string;
  condition: Condition;
};

const policies: Policy[] = [
  {
    effect: "allow",
    name: "Admin Full Access",
    description: "Cho phép admin mọi hành động",
    condition: {
      attribute: "$.user.roles",
      operator: "equals",
      value: "admin",
    },
  },
  {
    effect: "allow",
    name: "Owner allow edit",
    description: "Cho phép người sở hữu tạo",
    condition: {
      attribute: "$.user.id",
      operator: "equals",
      value: "$.resource.ownerId",
    },
  },
];

const tempContext: ABACContext = {
  user: {
    id: "123",
    roles: ["admin"],
  },
  action: "read",
  resource: {
    ownerId: "456",
  },
  environment: {
    ip: "192.168.1.200",
    timestamp: new Date(),
  },
};

class PolicyDecisionPoint {
  private policies: Policy[];
  constructor(policies: Policy[]) {
    this.policies = policies;
  }

  private getAttributeValue(context: ABACContext, attribute: string): any {
    if (!attribute.startsWith("$.")) return undefined;
    const parts = attribute.replace(/^\$./, "").split(".");
    let value = context;
    for (const part of parts) {
      if (value && typeof value === "object" && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }
    return value;
  }

  private evaluateCondition(context: ABACContext, condition: Condition) {
    if ("and" in condition) {
      return condition.and.every((subCondition) =>
        this.evaluateCondition(context, subCondition)
      );
    }

    if ("or" in condition) {
      return condition.or.some((subCondition) =>
        this.evaluateCondition(context, subCondition)
      );
    }

    if ("not" in condition) {
      return !this.evaluateCondition(context, condition.not);
    }

    const { attribute, operator, value } = condition;
  }

  public evaluate(context: ABACContext): "allow" | "deny" {
    console.log(this.getAttributeValue(context, "$.user.id"));
    return "allow";
  }
}

const test = new PolicyDecisionPoint(policies);

test.evaluate(tempContext);
