package main

// 真正的 Aho-Corasick 多模式匹配算法
// 时间复杂度: O(n + m + z)，n=文本长度, m=模式总长度, z=匹配数

type ACNode struct {
	children [256]*ACNode // ASCII 字符集
	fail     *ACNode
	output   []int // 匹配的模式索引
	depth    int
}

type AhoCorasick struct {
	root     *ACNode
	patterns []string
	lower    []string
}

func NewAhoCorasick(patterns []string) *AhoCorasick {
	ac := &AhoCorasick{
		root:     &ACNode{},
		patterns: patterns,
		lower:    make([]string, len(patterns)),
	}

	// 预计算小写版本
	for i, p := range patterns {
		ac.lower[i] = toLowerASCII(p)
	}

	// 构建 Trie
	for i, pattern := range ac.lower {
		ac.insert(pattern, i)
	}

	// 构建失败链接 (BFS)
	ac.buildFailLinks()

	return ac
}

func (ac *AhoCorasick) insert(pattern string, index int) {
	node := ac.root
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if node.children[c] == nil {
			node.children[c] = &ACNode{depth: node.depth + 1}
		}
		node = node.children[c]
	}
	node.output = append(node.output, index)
}

func (ac *AhoCorasick) buildFailLinks() {
	queue := make([]*ACNode, 0, 256)

	// 第一层节点的失败链接指向根
	for i := 0; i < 256; i++ {
		if ac.root.children[i] != nil {
			ac.root.children[i].fail = ac.root
			queue = append(queue, ac.root.children[i])
		}
	}

	// BFS 构建失败链接
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for c := 0; c < 256; c++ {
			child := current.children[c]
			if child == nil {
				continue
			}

			// 找失败链接
			failNode := current.fail
			for failNode != nil && failNode.children[c] == nil {
				failNode = failNode.fail
			}

			if failNode == nil {
				child.fail = ac.root
			} else {
				child.fail = failNode.children[c]
				// 合并输出
				if len(child.fail.output) > 0 {
					child.output = append(child.output, child.fail.output...)
				}
			}

			queue = append(queue, child)
		}
	}
}

// ContainsAny 快速检查是否包含任意模式 (最常用)
func (ac *AhoCorasick) ContainsAny(text string) bool {
	node := ac.root

	for i := 0; i < len(text); i++ {
		c := toLowerByte(text[i])

		// 沿失败链接回溯
		for node != ac.root && node.children[c] == nil {
			node = node.fail
		}

		if node.children[c] != nil {
			node = node.children[c]
		}

		// 检查是否有匹配
		if len(node.output) > 0 {
			return true
		}
	}

	return false
}

// ContainsAnyBytes 字节版本，避免字符串转换
func (ac *AhoCorasick) ContainsAnyBytes(text []byte) bool {
	node := ac.root

	for i := 0; i < len(text); i++ {
		c := toLowerByte(text[i])

		for node != ac.root && node.children[c] == nil {
			node = node.fail
		}

		if node.children[c] != nil {
			node = node.children[c]
		}

		if len(node.output) > 0 {
			return true
		}
	}

	return false
}

// FindAll 返回所有匹配的模式
func (ac *AhoCorasick) FindAll(text string) []string {
	var found []string
	seen := make(map[int]struct{}, 8)
	node := ac.root

	for i := 0; i < len(text); i++ {
		c := toLowerByte(text[i])

		for node != ac.root && node.children[c] == nil {
			node = node.fail
		}

		if node.children[c] != nil {
			node = node.children[c]
		}

		for _, idx := range node.output {
			if _, ok := seen[idx]; !ok {
				seen[idx] = struct{}{}
				found = append(found, ac.patterns[idx])
			}
		}
	}

	return found
}

// 快速 ASCII 小写转换 (无内存分配)
func toLowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = toLowerByte(s[i])
	}
	return string(b)
}
