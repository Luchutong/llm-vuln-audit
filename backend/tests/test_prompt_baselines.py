from audit.prompts import BUILTIN_PROMPTS


def test_lite_baselines_are_separate_minimum_compliance_versions():
    prompts = {prompt["id"]: prompt for prompt in BUILTIN_PROMPTS}
    p0 = prompts["P0-lite"]
    p1 = prompts["P1-lite"]

    assert p0["phase"] == p1["phase"] == "custom"
    assert p0["parent_id"] is None
    assert p1["parent_id"] == "P0-lite"
    assert "P0" in p0["reason"]
    assert "证据链" in p0["issues"][0]
    assert "输入来源 → 传播路径 → 危险操作" not in p0["text"]
    for prompt in (p0, p1):
        for section in ("# 一、审计角色", "# 二、核心任务", "# 三、漏洞判定标准", "# 四、输出格式"):
            assert section in prompt["text"]
        for category in ("SQL 注入", "反射型 XSS", "命令注入"):
            assert category in prompt["text"]
        assert "candidate" in prompt["text"]
        assert "POC" in prompt["text"]
        assert "修复建议" in prompt["text"]

    assert "参数化" in p1["text"]
    assert "不要求逐段证明输入到危险操作的传播链" in p1["issues"][0]
