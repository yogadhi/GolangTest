package errorhandler

//Block class
type Block struct {
	Try     func()
	Catch   func(Exception)
	Finally func()
}

//Exception interface
type Exception interface{}

//Throw function
func Throw(up Exception) {
	panic(up)
}

//Do function
func (tcf Block) Do() {
	if tcf.Finally != nil {

		defer tcf.Finally()
	}
	if tcf.Catch != nil {
		defer func() {
			if r := recover(); r != nil {
				tcf.Catch(r)
			}
		}()
	}
	tcf.Try()
}
