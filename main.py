import os
import json
import requests
import time
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path
import hashlib

@dataclass
class DetectionMetrics:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    true_cwe_positives: int = 0  # 正确识别的CWE类型次数
    total_cwe_positive_samples: int = 0  # 实际存在漏洞的样本总数

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator > 0 else 0.0
    
    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def cwe_accuracy(self) -> float:
        """计算CWE类型检测准确率（仅在存在漏洞时计算）"""
        return self.true_cwe_positives / self.total_cwe_positive_samples if self.total_cwe_positive_samples > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        """计算二分类准确率（有/无漏洞判断）"""
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total

class JavaVulnerabilityDetector:
    def __init__(self, api_key: str):
        self.api_url = "https://api.siliconflow.cn/v1/chat/completions"
        self.api_key = api_key
        self.cache_dir = Path(".cache/v3")  # 更新缓存版本
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.last_api_call_time = 0
        self.min_call_interval = 1.0
        self.valid_cwes = {"CWE-79", "CWE-89", "CWE-200", "CWE-284", "CWE-400"}

    def _call_llm_api(self, prompt: str, max_retries: int = 3) -> Optional[str]:
        cache_key = hashlib.md5(prompt.encode()).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)["response"]
        
        elapsed = time.time() - self.last_api_call_time
        if elapsed < self.min_call_interval:
            time.sleep(self.min_call_interval - elapsed)
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "Qwen/Qwen2.5-VL-72B-Instruct",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 1024
        }
        
        for attempt in range(max_retries):
            try:
                response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
                response.raise_for_status()
                result = response.json()["choices"][0]["message"]["content"]
                
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump({"prompt": prompt, "response": result}, f)
                
                self.last_api_call_time = time.time()
                return result
            except Exception as e:
                print(f"API调用失败 (尝试 {attempt+1}/{max_retries}): {str(e)}")
                time.sleep(2 ** attempt)
        return None

    def _build_detection_prompt(self, code: str) -> str:
        return f"""
    请严格分析以下Java代码中的漏洞，并按照指定格式回答。只需要关注以下五种漏洞类型：

- CWE-79: 跨站脚本（XSS） 
- CWE-89: SQL注入
- CWE-200: 信息泄露
- CWE-284: 不恰当的访问控制:
- CWE-400: 资源被过度消耗
代码：
{code}

请严格按以下格式回答：
1. 是否存在漏洞：是/否
2. 漏洞类型：CWE编号（从上述五种中选择一个，若无则填"无"）

要求：
- 每个漏洞类型单独分析后综合判断
- 选择最可能的那个
- 不要添加任何解释说明
- 可以着重考虑一下是不是有CWE-400，CWE-284   
"""

    def detect_vulnerabilities(self, code: str, file_path: str) -> Dict:
        prompt = self._build_detection_prompt(code)
        detection_result = self._call_llm_api(prompt)
        
        if not detection_result:
            return {"error": "API调用失败", "file": file_path}

        parsed_result = self._parse_detection_result(detection_result)
        return {
            "file": file_path,
            **parsed_result
        }

    def _parse_detection_result(self, result: str) -> Dict:
        vul_match = re.search(r'是否存在漏洞：\s*(是|否)', result)
        cwe_match = re.search(r'漏洞类型：\s*(CWE-\d+|无)', result)

        is_vulnerable = vul_match.group(1) == '是' if vul_match else False
        detected_cwe = cwe_match.group(1) if cwe_match else '无'

        result_data = {
            "is_vulnerable": False,
            "detected_cwe": "无"
        }

        if detected_cwe in self.valid_cwes:
            result_data.update({
                "is_vulnerable": True,
                "detected_cwe": detected_cwe
            })
        elif detected_cwe != "无":
            result_data["error"] = f"无效的CWE类型: {detected_cwe}"
        
        format_errors = []
        if not vul_match:
            format_errors.append("未找到漏洞存在性判断")
        if not cwe_match:
            format_errors.append("未找到CWE类型声明")
        
        if format_errors:
            result_data["error"] = "格式错误: " + ", ".join(format_errors)
        
        return result_data

def main():
    API_KEY = "sk-sgeswrumaayprlrxbldnqrgzyatzwexbuygpdufrcnrrdbhx"
    
    try:
        with open("java_vul_samples_50.json", "r", encoding="utf-8") as f:
            dataset = json.load(f)
    except Exception as e:
        print(f"数据集加载失败: {str(e)}")
        return
    
    detector = JavaVulnerabilityDetector(API_KEY)
    metrics = DetectionMetrics()

    for index, sample in enumerate(dataset[:50]):
        code = sample["func_before"]
        actual_cwes = sample.get("cwe_ids", [])
        result = detector.detect_vulnerabilities(code, f"Sample_{index+1}")

        if "error" in result:
            print(f"样本 {index+1} 检测出错：{result['error']}")
            continue

        is_vulnerable = result["is_vulnerable"]
        detected_cwe = result["detected_cwe"]
        true_vulnerability = len(actual_cwes) > 0

        # 更新CWE统计指标
        if true_vulnerability:
            metrics.total_cwe_positive_samples += 1
            if detected_cwe in actual_cwes:
                metrics.true_cwe_positives += 1

        # 二分类统计
        correct_detection = is_vulnerable and true_vulnerability
        is_fp = is_vulnerable and not true_vulnerability
        is_fn = not is_vulnerable and true_vulnerability
        is_tn = not is_vulnerable and not true_vulnerability

        if correct_detection:
            metrics.true_positives += 1
        elif is_fp:
            metrics.false_positives += 1
        elif is_fn:
            metrics.false_negatives += 1
        elif is_tn:
            metrics.true_negatives += 1

        print(f"\n样本 {index+1} 检测结果:")
        print(f"文件路径: {result['file']}")
        print(f"实际CWE: {actual_cwes}")
        print(f"检测到漏洞: {'是' if is_vulnerable else '否'}")
        print(f"检测类型: {detected_cwe}")
        if result.get("error"):
            print(f"解析警告: {result['error']}")
        print("="*50)

    print("\n=== 综合评估报告 ===")
    print(f"样本总数: {len(dataset[:50])}")
    print(f"TP: {metrics.true_positives}")
    print(f"FP: {metrics.false_positives}")
    print(f"TN: {metrics.true_negatives}")
    print(f"FN: {metrics.false_negatives}")
    print(f"精确率: {metrics.precision:.2f}")
    print(f"召回率: {metrics.recall:.2f}")
    print(f"F1值: {metrics.f1_score:.2f}")
    print(f"准确率: {metrics.accuracy:.2f}")  # 新增准确率输出
    print(f"CWE检测准确率: {metrics.cwe_accuracy:.2f} （基于{metrics.total_cwe_positive_samples}个实际存在漏洞的样本）")

if __name__ == "__main__":
    main()