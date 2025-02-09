enum ContextResourceEnum {
  POST = "post",
  USER = "user",
}

type ContextResource = {
  [ContextResourceEnum.POST]: {
    ownerId: string;
  };
  [ContextResourceEnum.USER]: {
    roles: string[];
    department: string;
  };
};

type BaseContext<R> = {
  user: {
    id: string;
    roles: string[];
  };
  resource: R;
  action: "read" | "write" | "edit" | "delete";
  environment: {
    ip: string;
    timestamp: Date;
  };
};

type ContextBuilder<T extends { [index: string]: any }> = {
  [M in keyof T]: T[M] extends object
    ? { type: M; context: BaseContext<T[M]> }
    : never;
};

type ABACContextBuilder =
  ContextBuilder<ContextResource>[keyof ContextBuilder<ContextResource>];

type Operator =
  | "equals"
  | "not_equal"
  | "contains"
  | "greater_than"
  | "greater_than_or_equal"
  | "less_than"
  | "less_than_or_equal"
  | "in";

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

class PolicyDecisionPoint {
  private policies: Policy[];
  constructor(policies: Policy[]) {
    this.policies = policies;
  }

  private getAttributeContextValue(
    context: ABACContextBuilder["context"],
    attribute: string
  ) {
    const parts = attribute.replace(/^\$./, "").split(".");
    let value: any = context;
    for (const part of parts) {
      if (value && typeof value === "object" && part in value) {
        value = value[part];
      } else {
        value = null;
      }
    }
    return value;
  }

  private getDynamicValue(
    context: ABACContextBuilder["context"],
    attribute: string
  ) {
    if (!attribute.startsWith("$.")) return null;
    return this.getAttributeContextValue(context, attribute);
  }

  private getConditionValue(
    value: any,
    context: ABACContextBuilder["context"]
  ) {
    if (typeof value == "string" && value.startsWith("$.")) {
      return this.getAttributeContextValue(context, value);
    } else {
      return value;
    }
  }

  private evaluateCondition(
    contextBuilder: ABACContextBuilder,
    condition: Condition
  ): boolean {
    if ("and" in condition) {
      return condition.and.every((subCondition) =>
        this.evaluateCondition(contextBuilder, subCondition)
      );
    }

    if ("or" in condition) {
      return condition.or.some((subCondition) =>
        this.evaluateCondition(contextBuilder, subCondition)
      );
    }

    if ("not" in condition) {
      return !this.evaluateCondition(contextBuilder, condition.not);
    }

    const { attribute, operator, value } = condition;

    const dynamicValue = this.getDynamicValue(
      contextBuilder.context,
      attribute
    );

    const conditionValue = this.getConditionValue(
      value,
      contextBuilder.context
    );

    if (!dynamicValue || !conditionValue) return false;

    switch (operator) {
      case "equals":
        return dynamicValue === conditionValue;
      case "not_equal":
        return dynamicValue !== conditionValue;
      case "greater_than":
        return dynamicValue > conditionValue;
      case "greater_than_or_equal":
        return dynamicValue >= conditionValue;
      case "less_than":
        return dynamicValue < conditionValue;
      case "less_than_or_equal":
        return dynamicValue <= conditionValue;
      case "in":
        return (
          Array.isArray(conditionValue) && conditionValue.includes(dynamicValue)
        );
      case "contains":
        return (
          Array.isArray(dynamicValue) && dynamicValue.includes(conditionValue)
        );
      default:
        return false;
    }
  }

  public evaluate(contextBuilder: ABACContextBuilder): "allow" | "deny" {
    let allow = false;
    let deny = false;

    for (const policy of this.policies) {
      const conditionsMet = this.evaluateCondition(
        contextBuilder,
        policy.condition
      );
      if (conditionsMet) {
        if (policy.effect === "deny") {
          deny = true;
        } else if (policy.effect === "allow") {
          allow = true;
        }
      }
    }

    return deny ? "deny" : allow ? "allow" : "deny";
  }
}

class PolicyEnforcementPoint {
  private pdp: PolicyDecisionPoint;

  constructor(pdp: PolicyDecisionPoint) {
    this.pdp = pdp;
  }

  public enforce(context: any): boolean {
    const decision = this.pdp.evaluate(context);
    return decision === "allow";
  }
}

const policies: Policy[] = [
  {
    effect: "allow",
    name: "Admin Full Access",
    description: "Cho phép admin mọi hành động",
    condition: {
      attribute: "$.user.roles",
      operator: "contains",
      value: "admin",
    },
  },
  {
    effect: "deny",
    name: "",
    description: "",
    condition: {
      not: {
        attribute: "$.environment.ip",
        operator: "equals",
        value: "192.168.1.200",
      },
    },
  },
];

const tempContext: ABACContextBuilder = {
  type: ContextResourceEnum.POST,
  context: {
    user: {
      id: "123",
      roles: ["admin"],
    },
    action: "delete",
    resource: {
      ownerId: "123",
    },
    environment: {
      ip: "192.168.1.200",
      timestamp: new Date(),
    },
  },
};

const test = new PolicyDecisionPoint(policies);
const pep = new PolicyEnforcementPoint(test);

console.log(pep.enforce(tempContext));
