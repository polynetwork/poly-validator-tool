package tool

func (t *Tool) RegMethods() {
	t.RegMethod("RegisterCandidate", RegisterCandidate)
	t.RegMethod("ApproveCandidate", ApproveCandidate)
	t.RegMethod("QuitNode", QuitNode)
	t.RegMethod("GenCommitDposTx", GenCommitDposTx)
	t.RegMethod("MultiSign", MultiSign)
	t.RegMethod("SendTx", SendTx)
	t.RegMethod("RegisterWhiteList", RegisterWhiteList)
	t.RegMethod("ApproveWhiteList", ApproveWhiteList)
}
