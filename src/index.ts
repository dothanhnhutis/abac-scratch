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
    name: "Owner allow edit",
    description: "Cho phép người sở hữu tạo",
    condition: {
      or: [
        {
          attribute: "$.user.id",
          operator: "equals",
          value: "$.resource.ownerId",
        },
        {
          attribute: "$.action",
          operator: "equals",
          value: "delete",
        },
      ],
    },
  },
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
];

const tempContext: ABACContext = {
  user: {
    id: "123",
    roles: ["admin1"],
  },
  action: "delete",
  resource: {
    ownerId: "123",
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

  private getAttributeValue(context: ABACContext, attribute: string) {
    if (!attribute.startsWith("$.")) return undefined;
    const parts = attribute.replace(/^\$./, "").split(".");
    let value: any = context;
    for (const part of parts) {
      if (value && typeof value === "object" && part in value) {
        value = value[part];
      } else {
        value = undefined;
      }
    }
    return value;
  }

  private evaluateCondition(
    context: ABACContext,
    condition: Condition
  ): boolean {
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

    const dynamicValue = this.getAttributeValue(context, attribute);
    const conditionValue =
      this.getAttributeValue(context, value) ||
      (value.startsWith("$.") ? undefined : value);

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
      case "not_in":
        return (
          Array.isArray(conditionValue) &&
          !conditionValue.includes(dynamicValue)
        );
      case "contains":
        return (
          Array.isArray(dynamicValue) && dynamicValue.includes(conditionValue)
        );
      default:
        return false; // Không hỗ trợ operator này
    }
  }

  public evaluate(context: ABACContext): "allow" | "deny" {
    let allow = false;
    let deny = false;

    for (const policy of this.policies) {
      const conditionsMet = this.evaluateCondition(context, policy.condition);
      console.log(conditionsMet);
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

const test = new PolicyDecisionPoint(policies);
const pep = new PolicyEnforcementPoint(test);

console.log(pep.enforce(tempContext));
