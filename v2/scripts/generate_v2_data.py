#!/usr/bin/env python3
"""
Network Security Expert v2 - Training Data Generator

Generates conceptual/theoretical training data with:
- Chain-of-thought reasoning
- Multi-turn conversations
- FireWeave function calling
- Compliance framework knowledge

Target: 20,000+ examples for FireWeave orchestration AI
"""

import os
import sys
import json
import argparse
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dotenv import load_dotenv

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from configs.v2_training_config import (
    V2_TOPICS,
    FIREWEAVE_FUNCTIONS,
    REASONING_TEMPLATES,
    GENERATION_SETTINGS
)

load_dotenv()

# =============================================================================
# SYSTEM PROMPTS FOR V2 DATA GENERATION
# =============================================================================

V2_SYSTEM_PROMPT = """You are an expert in generating high-quality training data for a Network Security AI assistant.

The AI being trained will power FireWeave - an enterprise firewall automation platform that:
- Manages Palo Alto Panorama, AWS, Azure, and GCP firewalls
- Provides AI-assisted policy management and natural language queries
- Performs attack path analysis and blast radius calculation
- Automates ServiceNow change request workflows
- Ensures compliance with PCI-DSS, SOC2, NIST, HIPAA, ISO 27001

CRITICAL REQUIREMENTS:
1. Focus on CONCEPTUAL and THEORETICAL knowledge - explain the WHY behind security decisions
2. Include chain-of-thought reasoning showing step-by-step analysis
3. Reference specific compliance frameworks and their requirements
4. Provide actionable guidance that can be executed via FireWeave
5. Use realistic enterprise scenarios (Fortune 500, healthcare, financial services)

The training data should help the AI:
- Understand security principles deeply (not just commands)
- Reason through complex multi-step workflows
- Make compliance-aware recommendations
- Orchestrate FireWeave's capabilities effectively
"""

CHAIN_OF_THOUGHT_PROMPT = """Generate training examples that include explicit reasoning steps.

Format the assistant's response to show thinking process:
1. First, understand what's being asked
2. Consider the security implications
3. Reference relevant compliance requirements
4. Analyze the options/trade-offs
5. Provide the recommendation with justification

Example structure:
"Let me analyze this step by step:

**Understanding the Request**: [what the user needs]

**Security Considerations**: [relevant security principles]

**Compliance Context**: [applicable framework requirements]

**Analysis**: [reasoning through the options]

**Recommendation**: [specific guidance with FireWeave actions]"
"""

FUNCTION_CALLING_PROMPT = """Generate examples where the assistant uses FireWeave functions to help the user.

Available FireWeave functions:
{functions}

When generating responses that involve function calls, format them as:

```json
{{
  "function": "function_name",
  "parameters": {{
    "param1": "value1",
    "param2": "value2"
  }},
  "reasoning": "Why this function is appropriate"
}}
```

Always explain WHY the function is being called and what the expected outcome is.
"""

MULTI_TURN_PROMPT = """Generate multi-turn conversations where the assistant:
1. Asks clarifying questions when needed
2. Builds on previous context
3. Guides the user through complex workflows
4. Provides follow-up recommendations

The conversation should feel natural and demonstrate deep understanding of:
- Network security principles
- Compliance requirements
- FireWeave platform capabilities
- Enterprise security operations
"""

# =============================================================================
# TOPIC-SPECIFIC GENERATION PROMPTS
# =============================================================================

def get_topic_prompt(topic_name: str, topic_config: dict) -> str:
    """Generate topic-specific prompt based on configuration."""

    base_prompt = f"""Generate high-quality Q&A training pairs for the topic: {topic_name}

Topic Description: {topic_config['description']}

Subtopics to cover:
{chr(10).join(f"- {st}" for st in topic_config['subtopics'])}

Requirements:
1. Focus on CONCEPTUAL understanding and THEORY
2. Explain the "WHY" behind security decisions
3. Reference real-world enterprise scenarios
4. Include compliance framework connections where relevant
5. Provide actionable guidance for FireWeave users
"""

    if topic_config.get('requires_chain_of_thought'):
        base_prompt += """
6. Include step-by-step reasoning in responses
7. Show the thought process for complex decisions
8. Consider trade-offs and alternatives
"""

    if 'fireweave' in topic_name.lower():
        base_prompt += """
FIREWEAVE CONTEXT:
- This is for users of FireWeave platform
- Include guidance on using FireWeave features
- Reference multi-cloud capabilities (Panorama, AWS, Azure, GCP)
- Consider ServiceNow integration workflows
- Think about attack path analysis and blast radius

Available FireWeave capabilities:
- Traffic flow analysis across all platforms
- Rule optimization (shadowed, unused, mergeable rules)
- Compliance scanning (PCI-DSS, SOC2, NIST, HIPAA)
- Attack path visualization and remediation
- ServiceNow ticket automation (35 seconds end-to-end)
- Multi-cloud topology visibility
"""

    if 'compliance' in topic_name.lower() or 'pci' in topic_name.lower() or 'soc2' in topic_name.lower() or 'nist' in topic_name.lower() or 'hipaa' in topic_name.lower() or 'iso' in topic_name.lower():
        base_prompt += """
COMPLIANCE FOCUS:
- Explain specific control requirements
- Provide evidence collection guidance
- Discuss audit preparation strategies
- Reference control mappings across frameworks
- Include remediation recommendations
"""

    return base_prompt


# =============================================================================
# DATA GENERATION CLASS
# =============================================================================

class V2DataGenerator:
    """Generates v2 training data with chain-of-thought reasoning."""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.client = None
        self.model = None
        self._setup_client()

    def _setup_client(self):
        """Initialize the API client based on provider."""
        if self.provider == "openai":
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY not found in environment")
            self.client = OpenAI(api_key=api_key)
            self.model = "gpt-4o"

        elif self.provider == "anthropic":
            from anthropic import Anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not found in environment")
            self.client = Anthropic(api_key=api_key)
            self.model = "claude-3-5-sonnet-20241022"

        elif self.provider == "mock":
            self.client = None
            self.model = "mock"

        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def generate_batch(
        self,
        topic_name: str,
        topic_config: dict,
        count: int = 10,
        include_cot: bool = True,
        include_functions: bool = False,
        multi_turn: bool = False
    ) -> List[dict]:
        """Generate a batch of training examples."""

        topic_prompt = get_topic_prompt(topic_name, topic_config)

        # Build the generation prompt
        generation_prompt = f"""{topic_prompt}

Generate {count} diverse, high-quality Q&A pairs.

{"Include chain-of-thought reasoning showing step-by-step analysis." if include_cot else ""}

{"Include FireWeave function calls where appropriate." if include_functions else ""}

{"Generate as multi-turn conversations (2-4 turns each)." if multi_turn else ""}

Output as valid JSON array:
[
  {{
    "question": "User's question or request",
    "answer": "Detailed response with reasoning and guidance",
    "topic": "{topic_name}",
    "has_reasoning": true/false,
    "has_function_call": true/false
  }}
]

IMPORTANT:
- Questions should be what a security professional would ask
- Answers must be detailed (500+ words for conceptual topics)
- Include real-world context and scenarios
- Reference specific frameworks, standards, or best practices
- Provide actionable guidance
"""

        if self.provider == "mock":
            return self._generate_mock_data(topic_name, count)

        try:
            if self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": V2_SYSTEM_PROMPT},
                        {"role": "user", "content": generation_prompt}
                    ],
                    temperature=0.8,
                    max_tokens=16000
                )
                content = response.choices[0].message.content

            elif self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=16000,
                    system=V2_SYSTEM_PROMPT,
                    messages=[
                        {"role": "user", "content": generation_prompt}
                    ]
                )
                content = response.content[0].text

            # Parse JSON from response
            return self._parse_response(content, topic_name)

        except Exception as e:
            print(f"  [ERROR] Generation failed: {e}")
            return []

    def _parse_response(self, content: str, topic_name: str) -> List[dict]:
        """Parse the API response into training examples."""
        try:
            # Find JSON array in response
            start_idx = content.find('[')
            end_idx = content.rfind(']') + 1

            if start_idx == -1 or end_idx == 0:
                print(f"  [WARN] No JSON array found in response")
                return []

            json_str = content[start_idx:end_idx]
            data = json.loads(json_str)

            # Validate and normalize
            examples = []
            for item in data:
                if 'question' in item and 'answer' in item:
                    examples.append({
                        'question': item['question'],
                        'answer': item['answer'],
                        'topic': item.get('topic', topic_name),
                        'has_reasoning': item.get('has_reasoning', True),
                        'has_function_call': item.get('has_function_call', False)
                    })

            return examples

        except json.JSONDecodeError as e:
            print(f"  [WARN] JSON parse error: {e}")
            return []

    def _generate_mock_data(self, topic_name: str, count: int) -> List[dict]:
        """Generate mock data for testing."""
        examples = []
        for i in range(count):
            examples.append({
                'question': f"[MOCK] Question {i+1} about {topic_name}",
                'answer': f"""[MOCK] Let me analyze this step by step:

**Understanding the Request**: This is a mock response for testing the v2 training pipeline.

**Security Considerations**: In a real scenario, we would discuss relevant security principles here.

**Compliance Context**: We would reference applicable frameworks like PCI-DSS, SOC2, or NIST.

**Analysis**: The mock generator would provide detailed analysis here, typically 500+ words.

**Recommendation**: Specific guidance for the {topic_name} topic would go here.""",
                'topic': topic_name,
                'has_reasoning': True,
                'has_function_call': False
            })
        return examples

    def convert_to_sharegpt(self, examples: List[dict]) -> List[dict]:
        """Convert examples to ShareGPT/ChatML format."""
        sharegpt_data = []
        for ex in examples:
            sharegpt_data.append({
                'conversations': [
                    {'from': 'human', 'value': ex['question']},
                    {'from': 'gpt', 'value': ex['answer']}
                ],
                'topic': ex.get('topic', 'unknown'),
                'has_reasoning': ex.get('has_reasoning', False),
                'has_function_call': ex.get('has_function_call', False)
            })
        return sharegpt_data


# =============================================================================
# MULTI-TURN CONVERSATION GENERATOR
# =============================================================================

class MultiTurnGenerator(V2DataGenerator):
    """Generates multi-turn conversation training data."""

    def generate_conversation(
        self,
        topic_name: str,
        topic_config: dict,
        max_turns: int = 4
    ) -> dict:
        """Generate a multi-turn conversation."""

        topic_prompt = get_topic_prompt(topic_name, topic_config)

        generation_prompt = f"""{topic_prompt}

Generate a realistic multi-turn conversation (2-{max_turns} turns) between a security professional and the AI assistant.

The conversation should:
1. Start with an initial question or request
2. Include follow-up questions that build on context
3. Show the assistant asking clarifying questions when appropriate
4. Demonstrate deep understanding of the topic
5. Include chain-of-thought reasoning in responses

Output as valid JSON:
{{
  "conversations": [
    {{"from": "human", "value": "Initial question"}},
    {{"from": "gpt", "value": "Response with reasoning"}},
    {{"from": "human", "value": "Follow-up question"}},
    {{"from": "gpt", "value": "Continued guidance"}}
  ],
  "topic": "{topic_name}",
  "scenario": "Brief description of the scenario"
}}

Make it realistic - as if a security engineer at a Fortune 500 company is using FireWeave.
"""

        if self.provider == "mock":
            return self._generate_mock_conversation(topic_name, max_turns)

        try:
            if self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": V2_SYSTEM_PROMPT + "\n" + MULTI_TURN_PROMPT},
                        {"role": "user", "content": generation_prompt}
                    ],
                    temperature=0.8,
                    max_tokens=8000
                )
                content = response.choices[0].message.content

            elif self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=8000,
                    system=V2_SYSTEM_PROMPT + "\n" + MULTI_TURN_PROMPT,
                    messages=[
                        {"role": "user", "content": generation_prompt}
                    ]
                )
                content = response.content[0].text

            # Parse JSON
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            if start_idx != -1 and end_idx > 0:
                return json.loads(content[start_idx:end_idx])

        except Exception as e:
            print(f"  [ERROR] Conversation generation failed: {e}")

        return None

    def _generate_mock_conversation(self, topic_name: str, max_turns: int) -> dict:
        """Generate mock multi-turn conversation."""
        return {
            'conversations': [
                {'from': 'human', 'value': f'[MOCK] How do I handle {topic_name} in our environment?'},
                {'from': 'gpt', 'value': f'[MOCK] Let me help you with {topic_name}. First, could you tell me about your current setup?'},
                {'from': 'human', 'value': '[MOCK] We use Palo Alto Panorama with AWS and Azure.'},
                {'from': 'gpt', 'value': f'[MOCK] Great! For your multi-cloud environment, here\'s my recommendation for {topic_name}...'}
            ],
            'topic': topic_name,
            'scenario': f'Mock scenario for {topic_name}'
        }


# =============================================================================
# FUNCTION CALLING EXAMPLE GENERATOR
# =============================================================================

class FunctionCallingGenerator(V2DataGenerator):
    """Generates training data with FireWeave function calls."""

    def generate_with_functions(
        self,
        topic_name: str,
        topic_config: dict,
        count: int = 5
    ) -> List[dict]:
        """Generate examples that include function calls."""

        functions_str = json.dumps(FIREWEAVE_FUNCTIONS, indent=2)

        generation_prompt = f"""Generate {count} Q&A pairs where the assistant uses FireWeave functions to help the user.

Topic: {topic_name}
Description: {topic_config['description']}

Available FireWeave Functions:
{functions_str}

Requirements:
1. The user asks something that requires FireWeave action
2. The assistant reasons about what's needed
3. The assistant calls appropriate FireWeave function(s)
4. The assistant explains the results and provides guidance

Output format:
[
  {{
    "question": "User request",
    "answer": "Response that includes function call and explanation",
    "functions_used": ["function_name1", "function_name2"],
    "topic": "{topic_name}"
  }}
]

Example answer format:
"Let me help you with that.

**Analysis**: [reasoning about the request]

**Action**: I'll use FireWeave to check this:

```json
{{
  "function": "check_traffic_flow",
  "parameters": {{
    "source_ip": "10.0.0.1",
    "destination_ip": "192.168.1.50",
    "port": 443,
    "protocol": "tcp"
  }}
}}
```

**Results**: [explanation of what this would return]

**Recommendation**: [guidance based on results]"
"""

        if self.provider == "mock":
            return self._generate_mock_function_data(topic_name, count)

        try:
            if self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": V2_SYSTEM_PROMPT + "\n" + FUNCTION_CALLING_PROMPT.format(functions=functions_str)},
                        {"role": "user", "content": generation_prompt}
                    ],
                    temperature=0.8,
                    max_tokens=12000
                )
                content = response.choices[0].message.content

            elif self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=12000,
                    system=V2_SYSTEM_PROMPT + "\n" + FUNCTION_CALLING_PROMPT.format(functions=functions_str),
                    messages=[
                        {"role": "user", "content": generation_prompt}
                    ]
                )
                content = response.content[0].text

            return self._parse_response(content, topic_name)

        except Exception as e:
            print(f"  [ERROR] Function calling generation failed: {e}")
            return []

    def _generate_mock_function_data(self, topic_name: str, count: int) -> List[dict]:
        """Generate mock function calling data."""
        examples = []
        for i in range(count):
            examples.append({
                'question': f"[MOCK] Check if traffic from web servers to database is allowed",
                'answer': f"""[MOCK] Let me help you verify that traffic path.

**Analysis**: You want to check connectivity between your web tier and database tier.

**Action**: I'll use FireWeave to analyze this:

```json
{{
  "function": "check_traffic_flow",
  "parameters": {{
    "source_ip": "10.1.1.0/24",
    "destination_ip": "10.2.1.100",
    "port": 5432,
    "protocol": "tcp"
  }}
}}
```

**Results**: Traffic is ALLOWED via rule "allow-web-to-db" in Device Group: Production

**Recommendation**: The traffic path is configured correctly. Consider enabling logging on this rule for audit purposes.""",
                'topic': topic_name,
                'functions_used': ['check_traffic_flow'],
                'has_function_call': True
            })
        return examples


# =============================================================================
# MAIN GENERATION ORCHESTRATOR
# =============================================================================

def generate_all_topics(
    provider: str = "openai",
    output_dir: str = "data/synthetic",
    batch_size: int = 10,
    delay: int = 5
):
    """Generate training data for all v2 topics."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize generators
    basic_gen = V2DataGenerator(provider)
    multi_gen = MultiTurnGenerator(provider)
    func_gen = FunctionCallingGenerator(provider)

    total_generated = 0
    total_target = sum(t['target_count'] for t in V2_TOPICS.values())

    print(f"\n{'='*60}")
    print(f"V2 TRAINING DATA GENERATION")
    print(f"{'='*60}")
    print(f"Provider: {provider}")
    print(f"Total topics: {len(V2_TOPICS)}")
    print(f"Target examples: {total_target:,}")
    print(f"Output directory: {output_path}")
    print(f"{'='*60}\n")

    for topic_name, topic_config in V2_TOPICS.items():
        target = topic_config['target_count']
        print(f"\n[TOPIC] {topic_name}")
        print(f"  Target: {target} examples")

        all_examples = []
        generated = 0

        # Calculate distribution
        cot_count = int(target * GENERATION_SETTINGS['chain_of_thought_ratio'])
        func_count = int(target * GENERATION_SETTINGS['function_calling_ratio'])
        multi_count = int(target * GENERATION_SETTINGS['multi_turn_ratio'])
        basic_count = target - func_count - multi_count

        # Generate basic Q&A with chain-of-thought
        print(f"  Generating {basic_count} basic Q&A...")
        batches = (basic_count + batch_size - 1) // batch_size
        for i in range(batches):
            count = min(batch_size, basic_count - i * batch_size)
            examples = basic_gen.generate_batch(
                topic_name, topic_config,
                count=count,
                include_cot=topic_config.get('requires_chain_of_thought', True)
            )
            all_examples.extend(examples)
            generated += len(examples)
            print(f"    Batch {i+1}/{batches}: +{len(examples)} (Total: {generated})")

            if provider != "mock" and i < batches - 1:
                time.sleep(delay)

        # Generate function calling examples (for FireWeave topics)
        if 'fireweave' in topic_name.lower() and func_count > 0:
            print(f"  Generating {func_count} function calling examples...")
            func_batches = (func_count + batch_size - 1) // batch_size
            for i in range(func_batches):
                count = min(batch_size, func_count - i * batch_size)
                examples = func_gen.generate_with_functions(
                    topic_name, topic_config, count=count
                )
                all_examples.extend(examples)
                generated += len(examples)
                print(f"    Batch {i+1}/{func_batches}: +{len(examples)} (Total: {generated})")

                if provider != "mock" and i < func_batches - 1:
                    time.sleep(delay)

        # Generate multi-turn conversations
        if multi_count > 0:
            print(f"  Generating {multi_count} multi-turn conversations...")
            for i in range(multi_count):
                conv = multi_gen.generate_conversation(
                    topic_name, topic_config,
                    max_turns=GENERATION_SETTINGS['max_turns_per_conversation']
                )
                if conv:
                    all_examples.append(conv)
                    generated += 1

                if provider != "mock" and i < multi_count - 1:
                    time.sleep(delay // 2)

        # Convert to ShareGPT format
        sharegpt_data = []
        for ex in all_examples:
            if 'conversations' in ex:
                sharegpt_data.append(ex)
            else:
                sharegpt_data.append({
                    'conversations': [
                        {'from': 'human', 'value': ex['question']},
                        {'from': 'gpt', 'value': ex['answer']}
                    ],
                    'topic': ex.get('topic', topic_name),
                    'has_reasoning': ex.get('has_reasoning', True),
                    'has_function_call': ex.get('has_function_call', False)
                })

        # Save to file
        output_file = output_path / f"{topic_name}_{provider}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sharegpt_data, f, indent=2, ensure_ascii=False)

        print(f"  [OK] Saved {len(sharegpt_data)} examples to {output_file.name}")
        total_generated += len(sharegpt_data)

    print(f"\n{'='*60}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"Total generated: {total_generated:,}")
    print(f"Target was: {total_target:,}")
    print(f"{'='*60}")


def generate_single_topic(
    topic_name: str,
    provider: str = "openai",
    output_dir: str = "data/synthetic",
    count: Optional[int] = None,
    batch_size: int = 10,
    delay: int = 5
):
    """Generate training data for a single topic."""

    if topic_name not in V2_TOPICS:
        print(f"Error: Unknown topic '{topic_name}'")
        print(f"Available topics: {', '.join(V2_TOPICS.keys())}")
        return

    topic_config = V2_TOPICS[topic_name]
    target = count or topic_config['target_count']

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"Generating: {topic_name}")
    print(f"Target: {target} examples")
    print(f"Provider: {provider}")
    print(f"{'='*60}\n")

    # Initialize generators
    basic_gen = V2DataGenerator(provider)
    func_gen = FunctionCallingGenerator(provider)

    all_examples = []

    # Calculate batches
    batches = (target + batch_size - 1) // batch_size

    for i in range(batches):
        count_this_batch = min(batch_size, target - i * batch_size)

        # Mix in function calling for FireWeave topics
        if 'fireweave' in topic_name.lower() and i % 3 == 2:
            examples = func_gen.generate_with_functions(
                topic_name, topic_config, count=count_this_batch
            )
        else:
            examples = basic_gen.generate_batch(
                topic_name, topic_config,
                count=count_this_batch,
                include_cot=topic_config.get('requires_chain_of_thought', True)
            )

        all_examples.extend(examples)
        print(f"  Batch {i+1}/{batches}: +{len(examples)} (Total: {len(all_examples)})")

        if provider != "mock" and i < batches - 1:
            time.sleep(delay)

    # Convert to ShareGPT
    sharegpt_data = []
    for ex in all_examples:
        if 'conversations' in ex:
            sharegpt_data.append(ex)
        else:
            sharegpt_data.append({
                'conversations': [
                    {'from': 'human', 'value': ex['question']},
                    {'from': 'gpt', 'value': ex['answer']}
                ],
                'topic': ex.get('topic', topic_name),
                'has_reasoning': ex.get('has_reasoning', True),
                'has_function_call': ex.get('has_function_call', False)
            })

    # Save
    output_file = output_path / f"{topic_name}_{provider}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sharegpt_data, f, indent=2, ensure_ascii=False)

    print(f"\n[SUCCESS] Generated {len(sharegpt_data)} examples")
    print(f"Saved to: {output_file}")


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate v2 training data with chain-of-thought reasoning"
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic", "mock"],
        default="openai",
        help="LLM provider for generation"
    )
    parser.add_argument(
        "--topic",
        type=str,
        help="Generate single topic (default: all topics)"
    )
    parser.add_argument(
        "--count",
        type=int,
        help="Override target count for topic"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="v2/data/synthetic",
        help="Output directory"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Examples per API call"
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=5,
        help="Seconds between API calls"
    )
    parser.add_argument(
        "--list-topics",
        action="store_true",
        help="List available topics"
    )

    args = parser.parse_args()

    if args.list_topics:
        print("\nV2 Training Topics:")
        print("=" * 60)
        for name, config in sorted(V2_TOPICS.items(), key=lambda x: x[1]['priority']):
            print(f"\n  {name}")
            print(f"    Priority: {config['priority']}")
            print(f"    Target: {config['target_count']} examples")
            print(f"    Description: {config['description'][:60]}...")
        return

    if args.topic:
        generate_single_topic(
            topic_name=args.topic,
            provider=args.provider,
            output_dir=args.output_dir,
            count=args.count,
            batch_size=args.batch_size,
            delay=args.delay
        )
    else:
        generate_all_topics(
            provider=args.provider,
            output_dir=args.output_dir,
            batch_size=args.batch_size,
            delay=args.delay
        )


if __name__ == "__main__":
    main()
