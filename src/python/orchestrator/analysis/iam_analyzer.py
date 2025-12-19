from typing import List, Dict, Any

class IAMAnalyzer:
    """
    Analyzes IAM policies for privilege escalation paths and dangerous permissions.
    """

    def check_privilege_escalation(self, policies: List[Dict[str, Any]]) -> List[str]:
        """
        Checks a list of policy documents for known privilege escalation primitives.
        Returns a list of finding descriptions.
        """
        findings = []
        
        # Aggregate all permissions from all policies
        all_actions = set()
        
        for policy in policies:
            doc = policy.get('Document', {})
            statements = doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
                
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        # Handle wildcards roughly
                        if action == '*':
                            all_actions.add('*')
                        else:
                            all_actions.add(action.lower())

        # Check for Primitives
        
        # 1. PassRole + RunInstances (The Classic)
        has_pass_role = 'iam:passrole' in all_actions or '*' in all_actions or 'iam:*' in all_actions
        has_run_instances = 'ec2:runinstances' in all_actions or '*' in all_actions or 'ec2:*' in all_actions
        
        if has_pass_role and has_run_instances:
            findings.append("Privilege Escalation: PassRole + RunInstances (Can create Admin EC2)")

        # 2. CreatePolicyVersion (Can edit policies)
        if 'iam:createpolicyversion' in all_actions or '*' in all_actions or 'iam:*' in all_actions:
            findings.append("Privilege Escalation: CreatePolicyVersion (Can edit managed policies)")

        # 3. SetDefaultPolicyVersion (Can restore vulnerable versions)
        if 'iam:setdefaultpolicyversion' in all_actions or '*' in all_actions or 'iam:*' in all_actions:
            findings.append("Privilege Escalation: SetDefaultPolicyVersion (Can restore vulnerable policy versions)")

        # 4. CreateAccessKey (Can create creds for others)
        if 'iam:createaccesskey' in all_actions or '*' in all_actions or 'iam:*' in all_actions:
            findings.append("Privilege Escalation: CreateAccessKey (Can create backdoor credentials)")

        # 5. PutUserPolicy (Can add inline policies)
        if 'iam:putuserpolicy' in all_actions or '*' in all_actions or 'iam:*' in all_actions:
            findings.append("Privilege Escalation: PutUserPolicy (Can add Admin inline policy)")
            
        # 6. UpdateLoginProfile (Can change passwords)
        if 'iam:updateloginprofile' in all_actions or '*' in all_actions or 'iam:*' in all_actions:
            findings.append("Privilege Escalation: UpdateLoginProfile (Can reset passwords)")

        return findings
